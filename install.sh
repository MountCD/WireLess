#!/usr/bin/env bash
# WireLess install script
# Run as root (or with sudo) on a Debian/Ubuntu system.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SINGBOX_BINARY="/usr/local/bin/sing-box"
ETC_DIR="/etc/wireless"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERR]${NC}   $*" >&2; }

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo ./install.sh)"
    exit 1
fi

# ── System packages ───────────────────────────────────────────────────────────
info "Installing system packages..."
apt-get update -qq
apt-get install -y -qq \
    wireguard-tools \
    iptables \
    iproute2 \
    curl \
    jq \
    python3 \
    python3-pip \
    python3-venv

# ── Python dependencies ───────────────────────────────────────────────────────
info "Installing Python dependencies..."
pip3 install --quiet --no-build-isolation -r "${SCRIPT_DIR}/requirements.txt"

# ── sing-box ──────────────────────────────────────────────────────────────────
if command -v sing-box &>/dev/null; then
    info "sing-box already installed: $(sing-box version | head -1)"
elif [[ -f "$SINGBOX_BINARY" ]]; then
    info "sing-box already at $SINGBOX_BINARY"
else
    info "Downloading sing-box (latest release)..."

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  SB_ARCH="amd64" ;;
        aarch64) SB_ARCH="arm64" ;;
        armv7l)  SB_ARCH="armv7" ;;
        *)
            error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    # Fetch latest release tag from GitHub API
    LATEST=$(curl -sSf "https://api.github.com/repos/SagerNet/sing-box/releases/latest" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])" 2>/dev/null \
        || echo "")

    if [[ -z "$LATEST" ]]; then
        error "Could not determine the latest sing-box version."
        error "Install sing-box >= 1.12 manually and retry."
        exit 1
    fi

    VER="${LATEST#v}"
    TARBALL="sing-box-${VER}-linux-${SB_ARCH}.tar.gz"
    URL="https://github.com/SagerNet/sing-box/releases/download/${LATEST}/${TARBALL}"

    TMP=$(mktemp -d)
    info "Downloading $URL ..."
    curl -sSfL "$URL" -o "${TMP}/${TARBALL}"
    tar -xzf "${TMP}/${TARBALL}" -C "$TMP"
    install -Dm755 "${TMP}/sing-box-${VER}-linux-${SB_ARCH}/sing-box" "$SINGBOX_BINARY"
    rm -rf "$TMP"

    # A broken/incompatible download must not be left behind as "installed".
    if ! "$SINGBOX_BINARY" version >/dev/null 2>&1; then
        error "Downloaded sing-box binary failed to run: $SINGBOX_BINARY"
        rm -f "$SINGBOX_BINARY"
        exit 1
    fi

    info "sing-box $LATEST installed at $SINGBOX_BINARY"
    info "$("$SINGBOX_BINARY" version | head -1)"
fi

# ── Directory structure ───────────────────────────────────────────────────────
info "Creating /etc/wireless directory structure..."
mkdir -p \
    "${ETC_DIR}/singbox" \
    "${ETC_DIR}/wireguard"
chmod 700 "${ETC_DIR}" "${ETC_DIR}/wireguard"
chmod 755 "${ETC_DIR}/singbox"

# ── Install wireless CLI ──────────────────────────────────────────────────────
info "Installing WireLess CLI (pip install -e)..."
pip3 install --quiet --no-build-isolation -e "${SCRIPT_DIR}"

# ── Verify ────────────────────────────────────────────────────────────────────
info "Verifying installation..."
python3 -m py_compile \
    "${SCRIPT_DIR}/wireless/parsers/vless.py" \
    "${SCRIPT_DIR}/wireless/parsers/vmess.py" \
    "${SCRIPT_DIR}/wireless/parsers/trojan.py" \
    "${SCRIPT_DIR}/wireless/parsers/hysteria2.py" \
    "${SCRIPT_DIR}/wireless/parsers/auto.py" \
    "${SCRIPT_DIR}/wireless/generators/singbox.py" \
    "${SCRIPT_DIR}/wireless/generators/wireguard.py" \
    "${SCRIPT_DIR}/wireless/models.py" \
    "${SCRIPT_DIR}/wireless/cli.py"

# The console script imports the package; verify it works outside the repo too.
if command -v wireless &>/dev/null; then
    if ! wireless --help >/dev/null 2>&1; then
        error "wireless CLI is not runnable. Re-run: sudo pip3 install -e ${SCRIPT_DIR}"
        exit 1
    fi
    info "CLI binary: $(command -v wireless)"
else
    warn "wireless command not in PATH yet — restart shell or check your PATH"
fi

echo
info "✅ WireLess installed successfully!"
echo
echo "Quick start:"
echo "  wireless add 'vless://...#MyProxy'"
echo "  wireless use MyProxy"
echo "  wireless start"
echo "  wireless client --qr"
echo
