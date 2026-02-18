#!/usr/bin/env bash
# Run the Azure AD email enumeration Python script.
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
exec python3 enum_email.py "$@"
