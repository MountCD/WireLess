#!/usr/bin/env bash
# WireLess — Arch Linux install script
# Usage: sudo ./install-arch.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SINGBOX_BINARY="/usr/local/bin/sing-box"
ETC_DIR="/etc/wireless"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERR]${NC}   $*" >&2; }
step()  { echo -e "\n${CYAN}──── $* ────${NC}"; }

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo ./install-arch.sh)"
    exit 1
fi

# ── Detect real user (for AUR / python user installs) ────────────────────────
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

# ── System packages via pacman ────────────────────────────────────────────────
step "Installing system packages via pacman"
if ! pacman -S --needed --noconfirm \
    wireguard-tools \
    iptables \
    iproute2 \
    curl \
    jq \
    python \
    python-pip \
    python-setuptools \
    python-wheel \
    ca-certificates; then
    error "Failed to install packages. Run 'pacman -Syu' and retry."
    exit 1
fi

# ── sing-box ──────────────────────────────────────────────────────────────────
step "Installing sing-box"

# Prefer AUR / community package if already installed
if command -v sing-box &>/dev/null; then
    info "sing-box already installed: $(sing-box version | head -1)"
else
    # Try installing from AUR via yay/paru if available (run as REAL_USER)
    AUR_HELPER=""
    for helper in yay paru aura; do
        if su -c "command -v $helper" "$REAL_USER" &>/dev/null; then
            AUR_HELPER="$helper"
            break
        fi
    done

    if [[ -n "$AUR_HELPER" ]]; then
        info "Found AUR helper: $AUR_HELPER — installing sing-box-bin from AUR..."
        su -c "$AUR_HELPER -S --needed --noconfirm sing-box-bin" "$REAL_USER" \
            || warn "AUR install failed, falling back to GitHub release"
    fi

    # Fallback: download binary from GitHub releases
    if ! command -v sing-box &>/dev/null; then
        info "Downloading sing-box binary from GitHub releases..."

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

        LATEST=$(curl -sSf "https://api.github.com/repos/SagerNet/sing-box/releases/latest" \
            | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])" 2>/dev/null \
            || echo "")

        if [[ -z "$LATEST" ]]; then
            error "Could not determine the latest sing-box version."
            error "Install sing-box >= 1.12 manually (pacman/AUR) and retry."
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

        info "sing-box ${LATEST} installed at $SINGBOX_BINARY"
        info "$("$SINGBOX_BINARY" version | head -1)"
    fi
fi

# ── Python dependencies ───────────────────────────────────────────────────────
step "Installing Python dependencies"

# On Arch we prefer --break-system-packages or venv; check if in venv first
if python3 -c "import sys; sys.exit(0 if sys.prefix != sys.base_prefix else 1)" 2>/dev/null; then
    info "Virtual environment detected — installing normally"
    pip install --quiet --no-build-isolation -r "${SCRIPT_DIR}/requirements.txt"
else
    info "Installing with --break-system-packages (Arch externally-managed)"
    pip install --quiet --break-system-packages --no-build-isolation -r "${SCRIPT_DIR}/requirements.txt"
fi

# ── Directory structure ───────────────────────────────────────────────────────
step "Creating /etc/wireless directory structure"
install -dm700 "${ETC_DIR}"
install -dm700 "${ETC_DIR}/wireguard"
install -dm755 "${ETC_DIR}/singbox"

# ── Install wireless CLI ──────────────────────────────────────────────────────
step "Installing WireLess CLI"

if python3 -c "import sys; sys.exit(0 if sys.prefix != sys.base_prefix else 1)" 2>/dev/null; then
    pip install --quiet --no-build-isolation -e "${SCRIPT_DIR}"
else
    pip install --quiet --break-system-packages --no-build-isolation -e "${SCRIPT_DIR}"
fi

# ── Verify ────────────────────────────────────────────────────────────────────
step "Verifying installation"
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
        error "wireless CLI is not runnable. Re-run: sudo pip install --break-system-packages -e ${SCRIPT_DIR}"
        exit 1
    fi
    info "CLI binary: $(command -v wireless)"
else
    warn "wireless command not in PATH yet — restart shell or check your PATH"
fi

echo
info "✅ WireLess installed successfully on Arch Linux!"
echo
echo "Quick start:"
echo "  wireless add 'vless://...#MyProxy'"
echo "  wireless use MyProxy"
echo "  sudo wireless start"
echo "  wireless client --qr"
echo
