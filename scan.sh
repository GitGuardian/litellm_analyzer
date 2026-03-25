#!/bin/sh
set -eu

# ---------------------------------------------------------------------------
# scan.sh – harvest credentials and scan with ggshield, creating incidents
#           in the GitGuardian dashboard.
#
# Usage:
#   sh scan.sh --source-name NAME [--output OUTPUT.zip]
#
# Environment:
#   GITGUARDIAN_API_KEY  API token (required for source creation and permission
#                        checks; if not set, stored ggshield credentials are
#                        used for the scan but source creation will be skipped)
# ---------------------------------------------------------------------------

GG_API="https://api.gitguardian.com"
SOURCE_NAME=""
OUTPUT_ZIP="harvested_credentials.zip"
SCRIPT_DIR="$(dirname "$0")"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "[*] $*"; }

usage() {
    cat >&2 <<EOF
Usage: $0 --source-name NAME [--output OUTPUT.zip]

Options:
  --source-name NAME   (required) GitGuardian source name to create
  --output PATH        Output ZIP path for gather_files.py
                       (default: harvested_credentials.zip)

Environment:
  GITGUARDIAN_API_KEY  GitGuardian API token; if not set, ggshield stored
                       credentials are used (source creation requires the key)
EOF
    exit 1
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --source-name) SOURCE_NAME="${2:?'--source-name requires a value'}"; shift 2 ;;
        --output)      OUTPUT_ZIP="${2:?'--output requires a value'}"; shift 2 ;;
        -h|--help)     usage ;;
        *) die "Unknown argument: $1" ;;
    esac
done

[ -n "$SOURCE_NAME" ] || die "--source-name is required"

# ---------------------------------------------------------------------------
# Step 1: Install ggshield if not present
# ---------------------------------------------------------------------------
if ! command -v ggshield > /dev/null 2>&1; then
    case "$(uname -s)" in
        Darwin)
            info "ggshield not found, installing via Homebrew..."
            command -v brew > /dev/null 2>&1 \
                || die "Homebrew is required to install ggshield on macOS. Install it from https://brew.sh"
            brew install ggshield \
                || die "Failed to install ggshield via Homebrew"
            ;;
        *)
            info "ggshield not found, installing via pip..."
            pip install ggshield 2>/dev/null || pip3 install ggshield \
                || die "Failed to install ggshield. Install it manually: pip install ggshield"
            ;;
    esac
fi
ggshield_version=$(ggshield --version 2>&1 | head -1) \
    || die "ggshield command failed. Ensure it is correctly installed."
info "ggshield $ggshield_version"

# ---------------------------------------------------------------------------
# Step 2: Authentication
# ---------------------------------------------------------------------------
GG_API_KEY="${GITGUARDIAN_API_KEY:-}"

if [ -n "$GG_API_KEY" ]; then
    info "Using GITGUARDIAN_API_KEY from environment"
    export GITGUARDIAN_API_KEY="$GG_API_KEY"
else
    info "GITGUARDIAN_API_KEY not set — checking stored ggshield credentials..."
    if ! ggshield auth status > /dev/null 2>&1; then
        info "Not authenticated. Launching ggshield auth login..."
        ggshield auth login --scopes "scan scan:create-incidents sources:write" || die "Authentication failed"
    fi
    info "ggshield is authenticated via stored credentials"
fi

# ---------------------------------------------------------------------------
# Step 3: Verify token permissions (requires API key)
# ---------------------------------------------------------------------------
if [ -n "$GG_API_KEY" ]; then
    info "Verifying token permissions..."

    TOKEN_INFO=$(curl -sf \
        -H "Authorization: Token $GG_API_KEY" \
        "$GG_API/v1/token") \
        || die "Failed to reach GitGuardian API — check your token and network"

    MISSING=$(python3 - "$TOKEN_INFO" <<'PYEOF'
import sys, json
info = json.loads(sys.argv[1])
scopes = info.get("scope", [])
required = ["scan", "scan:create-incidents", "write:source"]
missing = [s for s in required if s not in scopes]
if missing:
    print(" ".join(missing))
PYEOF
)

    if [ -n "$MISSING" ]; then
        die "Token is missing required scope(s): $MISSING"
    fi
    info "Token permissions OK ("scan:create-incidents", "sources:write")"
fi

# ---------------------------------------------------------------------------
# Step 4: Create source
# ---------------------------------------------------------------------------
if [ -z "$GG_API_KEY" ]; then
    die "Creating a source requires GITGUARDIAN_API_KEY to be set"
fi

info "Creating source '$SOURCE_NAME'..."
SOURCE_RESP=$(curl -sf -X POST \
    -H "Authorization: Token $GG_API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"$SOURCE_NAME\"}" \
    "$GG_API/v1/sources/custom-sources") \
    || die "Failed to create source '$SOURCE_NAME'"

SOURCE_UUID=$(python3 -c "import sys,json; print(json.loads(sys.argv[1])['source_uuid'])" "$SOURCE_RESP") \
    || die "Could not parse source UUID from API response"

info "Source created — UUID: $SOURCE_UUID"

# ---------------------------------------------------------------------------
# Step 5: Harvest credentials
# ---------------------------------------------------------------------------
info "Running gather_files.py → $OUTPUT_ZIP"
python3 "$SCRIPT_DIR/gather_files.py" "$OUTPUT_ZIP" \
    || die "gather_files.py failed"
info "Archive ready: $OUTPUT_ZIP"

# ---------------------------------------------------------------------------
# Step 6: Scan with ggshield
# ---------------------------------------------------------------------------
info "Scanning archive with ggshield (--create-incidents)..."
ggshield secret scan archive \
    --source-uuid "$SOURCE_UUID" \
    "$OUTPUT_ZIP"

info "Scan complete."
