#!/usr/bin/env python3
"""
Azure AD / Entra ID enumeration for a given email address.
Runs the process described in this repo's README (tenant discovery, domain realm,
GetCredentialType, OneDrive probe, Autodiscover V2/V1).
"""

import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from urllib.parse import quote

try:
    import requests
except ImportError:
    print("Error: 'requests' is required. Install with: pip install requests", file=sys.stderr)
    sys.exit(1)

DEFAULT_EMAIL = "jcoan@cybermaxx.com"
# (connect_seconds, read_seconds) so slow DNS/TCP doesn't hang the script
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 10
REQUEST_TIMEOUT = (CONNECT_TIMEOUT, READ_TIMEOUT)
# Shorter for Autodiscover V1 (hits custom domain that often doesn't exist)
AUTODISCOVER_V1_TIMEOUT = (4, 6)
USER_AGENT = "Mozilla/5.0 (compatible; AzureADEnum/1.0)"


def get_email_input() -> str:
    """Prompt for email with default; validate format."""
    prompt = f"Email address [{DEFAULT_EMAIL}]: "
    raw = input(prompt).strip()
    email = raw if raw else DEFAULT_EMAIL
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        print(f"Invalid email format: {email}", file=sys.stderr)
        sys.exit(1)
    return email


def domain_from_email(email: str) -> str:
    """Extract domain from email (e.g. user@example.com -> example.com)."""
    return email.split("@", 1)[1].lower()


def tenant_name_from_domain(domain: str) -> str:
    """Best-effort tenant name for OneDrive/SharePoint (e.g. example.com -> example)."""
    return domain.split(".")[0].lower()


def user_path_from_email(email: str) -> str:
    """OneDrive user path: local_part@domain -> local_part_domain with . and @ -> _."""
    local, domain = email.lower().split("@", 1)
    path = f"{local}_{domain.replace('.', '_')}"
    return path


def section(title: str) -> None:
    print(f"\n{'='*60}\n{title}\n{'='*60}")
    sys.stdout.flush()


def run_tenant_discovery(domain: str) -> dict | None:
    """1. Tenant discovery: azmap.dev + OpenID config."""
    section("1. Tenant Discovery")
    out = {}
    # 1.1 azmap.dev
    url = f"https://azmap.dev/api/tenant?domain={quote(domain)}&extract=true"
    try:
        r = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        r.raise_for_status()
        data = r.json()
        out["azmap"] = data
        print("azmap.dev:", json.dumps(data, indent=2))
    except Exception as e:
        print(f"azmap.dev error: {e}")
        out["azmap"] = None

    # 1.2 OpenID
    url = f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
    try:
        r = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        r.raise_for_status()
        data = r.json()
        out["openid"] = data
        print("OpenID config: token_endpoint =", data.get("token_endpoint"))
    except Exception as e:
        print(f"OpenID error: {e}")
        out["openid"] = None

    return out


def run_domain_realm(email: str, domain: str) -> dict | None:
    """2. Domain realm (getuserrealm) using the email as login."""
    section("2. Domain Realm Information")
    url = f"https://login.microsoftonline.com/getuserrealm.srf?login={quote(email)}&json=1"
    try:
        r = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        r.raise_for_status()
        data = r.json()
        print(json.dumps(data, indent=2))
        return data
    except Exception as e:
        print(f"Domain realm error: {e}")
        return None


def run_get_credential_type(email: str) -> dict | None:
    """3. User enumeration via GetCredentialType."""
    section("3. User Enumeration (GetCredentialType)")
    url = "https://login.microsoftonline.com/common/GetCredentialType"
    payload = {
        "Username": email,
        "isOtherIdpSupported": True,
        "checkPhones": False,
        "isRemoteNGCSupported": True,
        "isCookieBannerShown": False,
        "isFidoSupported": True,
        "originalRequest": "",
        "country": "US",
        "forceotclogin": False,
        "isExternalFederationDisallowed": False,
        "isRemoteConnectSupported": False,
        "federationFlags": 0,
        "isSignup": False,
        "flowToken": "",
        "isAccessPassSupported": True,
    }
    codes = {
        0: "User exists (Azure IdP)",
        1: "User does not exist",
        2: "Invalid request",
        4: "Server error",
        5: "User exists (Federated IdP)",
        6: "User exists (External non-MS IdP)",
    }
    try:
        r = requests.post(
            url,
            json=payload,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
        )
        r.raise_for_status()
        data = r.json()
        code = data.get("IfExistsResult", data.get("IfExistsResult", "?"))
        print("Response:", json.dumps(data, indent=2))
        print("IfExistsResult:", code, "->", codes.get(code, "Unknown"))
        return data
    except Exception as e:
        print(f"GetCredentialType error: {e}")
        return None


def run_onedrive_enum(email: str, domain: str, tenant_override: str | None = None) -> None:
    """5. OneDrive user enumeration (HEAD request)."""
    section("5. OneDrive User Enumeration")
    tenant = tenant_override or tenant_name_from_domain(domain)
    user_path = user_path_from_email(email)
    url = f"https://{tenant}-my.sharepoint.com/personal/{user_path}/_layouts/15/onedrive.aspx"
    print(f"URL: {url}")
    try:
        r = requests.head(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=False,
        )
        sc = r.status_code
        if sc == 200:
            print("Result: 200 -> User exists, OneDrive accessible")
        elif sc in (401, 403):
            print("Result: {} -> User exists, access denied".format(sc))
        elif sc == 404:
            print("Result: 404 -> User does not exist")
        else:
            print(f"Result: HTTP {sc}")
    except Exception as e:
        print(f"OneDrive probe error: {e}")


def run_autodiscover_v2(email: str) -> None:
    """9. Autodiscover V2 (JSON) user enumeration."""
    section("9. Autodiscover V2 Enumeration")
    url = (
        "https://autodiscover-s.outlook.com/autodiscover/autodiscover.json"
        f"?Email={quote(email)}&Protocol=Autodiscoverv1"
    )
    try:
        r = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=False,
        )
        sc = r.status_code
        if sc == 200:
            print("Result: 200 -> User exists")
        elif sc == 302:
            print("Result: 302 (redirect) -> User does not exist")
        elif sc in (401, 403):
            print("Result: {} -> User exists (auth required)".format(sc))
        else:
            print(f"Result: HTTP {sc}")
    except Exception as e:
        print(f"Autodiscover V2 error: {e}")


def _do_autodiscover_v1_request(url: str, body: str) -> requests.Response:
    return requests.post(
        url,
        data=body,
        timeout=AUTODISCOVER_V1_TIMEOUT,
        headers={
            "User-Agent": USER_AGENT,
            "Content-Type": "text/xml; charset=utf-8",
        },
    )


def run_autodiscover_v1(email: str, domain: str) -> None:
    """10. Autodiscover V1 (XML) user enumeration. Run in thread to cap DNS/connect hang."""
    section("10. Autodiscover V1 Enumeration")
    url = f"https://autodiscover.{domain}/autodiscover/autodiscover.xml"
    body = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">\n'
        "  <Request>\n"
        f"    <EMailAddress>{email}</EMailAddress>\n"
        "    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>\n"
        "  </Request>\n"
        "</Autodiscover>"
    )
    print(f"Requesting {url} (max 12s)...")
    sys.stdout.flush()
    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(_do_autodiscover_v1_request, url, body)
            r = fut.result(timeout=12)
        sc = r.status_code
        text = (r.text or "")[:500]
        print(f"HTTP {sc}")
        if "RedirectAddr" in text or "NoError" in text:
            print("Indicators: User may exist (RedirectAddr/NoError)")
        elif "InvalidUser" in text:
            print("Indicators: User does not exist (InvalidUser)")
        else:
            print("Response snippet:", text[:300])
    except FuturesTimeoutError:
        print("Autodiscover V1 error: timed out after 12s (DNS or server may be slow/unreachable)")
    except Exception as e:
        print(f"Autodiscover V1 error: {e}")


def main() -> None:
    email = get_email_input()
    domain = domain_from_email(email)
    print(f"\nUsing email: {email}")
    print(f"Domain: {domain}")

    tenant_data = run_tenant_discovery(domain)
    tenant_id = None
    tenant_display = None
    if tenant_data and tenant_data.get("azmap"):
        az = tenant_data["azmap"]
        tenant_id = az.get("tenantId")
        tenant_display = az.get("displayName")

    run_domain_realm(email, domain)
    run_get_credential_type(email)

    # OneDrive: prefer tenant name from azmap if available (some APIs return a slug)
    tenant_for_onedrive = None
    if tenant_display:
        tenant_for_onedrive = re.sub(r"[^a-z0-9]", "", tenant_display.lower())[:30] or None
    run_onedrive_enum(email, domain, tenant_override=tenant_for_onedrive)

    run_autodiscover_v2(email)
    run_autodiscover_v1(email, domain)

    print("\n" + "=" * 60)
    print("Enumeration complete.")
    print("=" * 60)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
