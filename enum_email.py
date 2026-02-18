#!/usr/bin/env python3
"""
Azure AD / Entra ID enumeration for a given email address.
Runs the process described in this repo's README (tenant discovery, domain realm,
GetCredentialType, OneDrive probe, Autodiscover V2).
"""

import json
import re
import sys
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
    try:
        r = requests.post(
            url,
            json=payload,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
        )
        r.raise_for_status()
        data = r.json()
        code = data.get("IfExistsResult", "?")
        print("Response:", json.dumps(data, indent=2))
        print("IfExistsResult:", code, "->", CREDENTIAL_TYPE_LABELS.get(code, "Unknown"))
        return data
    except Exception as e:
        print(f"GetCredentialType error: {e}")
        return None


def run_onedrive_enum(email: str, domain: str, tenant_override: str | None = None) -> str:
    """5. OneDrive user enumeration (HEAD request). Returns short summary line."""
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
            return "200 – user exists, OneDrive accessible"
        elif sc in (401, 403):
            print("Result: {} -> User exists, access denied".format(sc))
            return f"{sc} – user exists, access denied"
        elif sc == 404:
            print("Result: 404 -> User does not exist")
            return "404 – user does not exist"
        else:
            print(f"Result: HTTP {sc}")
            return f"HTTP {sc}"
    except Exception as e:
        print(f"OneDrive probe error: {e}")
        return f"Error: {e}"


def run_autodiscover_v2(email: str) -> str:
    """9. Autodiscover V2 (JSON) user enumeration. Returns short summary line."""
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
            return "200 – user exists"
        elif sc == 302:
            print("Result: 302 (redirect) -> User does not exist")
            return "302 – user does not exist"
        elif sc in (401, 403):
            print("Result: {} -> User exists (auth required)".format(sc))
            return f"{sc} – user exists (auth required)"
        else:
            print(f"Result: HTTP {sc}")
            return f"HTTP {sc}"
    except Exception as e:
        print(f"Autodiscover V2 error: {e}")
        return f"Error: {e}"


CREDENTIAL_TYPE_LABELS = {
    0: "User exists (Azure IdP)",
    1: "User does not exist",
    2: "Invalid request",
    4: "Server error",
    5: "User exists (Federated IdP)",
    6: "User exists (External non-MS IdP)",
}


def print_summary(
    email: str,
    domain: str,
    tenant_data: dict | None,
    realm_data: dict | None,
    credential_data: dict | None,
    onedrive_summary: str,
    autodiscover_v2_summary: str,
) -> None:
    """Print a concise summary of all enumeration results."""
    section("SUMMARY")
    print(f"  Email:        {email}")
    print(f"  Domain:       {domain}")
    print()

    if tenant_data and tenant_data.get("azmap"):
        az = tenant_data["azmap"]
        print(f"  Tenant:       {az.get('displayName', '—')}")
        print(f"  Tenant ID:    {az.get('tenantId', '—')}")
        print(f"  Country:      {az.get('countryCode', '—')}")
    else:
        print("  Tenant:       (not found or error)")
    print()

    if realm_data:
        ns = realm_data.get("NameSpaceType", "—")
        brand = realm_data.get("FederationBrandName", "—")
        print(f"  Realm:        {ns}")
        print(f"  Brand:        {brand}")
    else:
        print("  Realm:        (error or not found)")
    print()

    if credential_data is not None and "IfExistsResult" in credential_data:
        code = credential_data["IfExistsResult"]
        print(f"  GetCredentialType: {CREDENTIAL_TYPE_LABELS.get(code, code)}")
    else:
        print("  GetCredentialType: (error or not found)")
    print()

    print(f"  OneDrive:         {onedrive_summary}")
    print(f"  Autodiscover V2:  {autodiscover_v2_summary}")
    print()
    print("  Enumeration complete.")
    sys.stdout.flush()


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

    realm_data = run_domain_realm(email, domain)
    credential_data = run_get_credential_type(email)

    # OneDrive: prefer tenant name from azmap if available (some APIs return a slug)
    tenant_for_onedrive = None
    if tenant_display:
        tenant_for_onedrive = re.sub(r"[^a-z0-9]", "", tenant_display.lower())[:30] or None
    onedrive_summary = run_onedrive_enum(email, domain, tenant_override=tenant_for_onedrive)

    autodiscover_v2_summary = run_autodiscover_v2(email)

    print_summary(
        email,
        domain,
        tenant_data,
        realm_data,
        credential_data,
        onedrive_summary,
        autodiscover_v2_summary,
    )


if __name__ == "__main__":
    main()
