#!/usr/bin/env bash
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[*] $*"; }

GG_API="https://api.gitguardian.com"

TOKEN_INFO=$(curl -sf \
    -H "Authorization: Token $GITGUARDIAN_API_KEY" \
    "$GG_API/v1/token") \
    || die "Failed to reach GitGuardian API — check your token and network"
MISSING=$(python3 - "$TOKEN_INFO" <<'PYEOF'
import sys, json
info = json.loads(sys.argv[1])
scopes = info.get("scope", [])
required = ["scan", "write:source", "write:incident"]
missing = [s for s in required if s not in scopes]
if missing:
    print(" ".join(missing))
PYEOF
)

if [ -n "$MISSING" ]; then
    die "Token is missing required scope(s): $MISSING"
fi
info "Token permissions OK"