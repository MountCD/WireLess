# Maintainer: Your Name <your@email.com>
# Contributor: Your Name <your@email.com>

pkgname=wireless
pkgver=0.1.0
pkgrel=1
pkgdesc="WireGuard gateway for proxy protocols: VLESS, VMess, Trojan, Hysteria2, TUIC"
arch=('x86_64' 'aarch64' 'armv7h')
url="https://github.com/YourUser/WireLess"
license=('MIT')

# Runtime dependencies
depends=(
    'python'
    'python-click'
    'python-requests'
    'python-pillow'   # for qrcode[pil]
    'wireguard-tools'
    'iptables'
    'iproute2'
    'sing-box>=1.12.0'  # from AUR: sing-box or sing-box-bin
)

# Build/check dependencies
makedepends=(
    'python-setuptools'
    'python-build'
    'python-installer'
    'python-wheel'
)

# Optional: for QR code output in terminal
optdepends=(
    'python-qrcode: QR code generation for wireless client --qr'
    'zbar: scan QR codes'
)

# For AUR: uncomment and set source to git or tarball
# For local testing with makepkg: use local source
source=(
    # AUR (tarball from GitHub releases):
    # "${pkgname}-${pkgver}.tar.gz::https://github.com/YourUser/WireLess/archive/v${pkgver}.tar.gz"

    # Local development (makepkg -e from project root):
    "wireless-cli=wireless/cli.py"
    "wireless-config=wireless/config.py"
    "wireless-models=wireless/models.py"
    "wireless-init=wireless/__init__.py"
    # parsers
    "wireless-parsers-init=wireless/parsers/__init__.py"
    "wireless-parsers-base=wireless/parsers/base.py"
    "wireless-parsers-auto=wireless/parsers/auto.py"
    "wireless-parsers-vless=wireless/parsers/vless.py"
    "wireless-parsers-vmess=wireless/parsers/vmess.py"
    "wireless-parsers-trojan=wireless/parsers/trojan.py"
    "wireless-parsers-hysteria2=wireless/parsers/hysteria2.py"
    # generators
    "wireless-generators-init=wireless/generators/__init__.py"
    "wireless-generators-singbox=wireless/generators/singbox.py"
    "wireless-generators-wireguard=wireless/generators/wireguard.py"
    # managers
    "wireless-managers-init=wireless/managers/__init__.py"
    "wireless-managers-wg=wireless/managers/wireguard.py"
    "wireless-managers-sb=wireless/managers/singbox.py"
    "wireless-managers-rt=wireless/managers/routing.py"
    # packaging
    "pyproject.toml"
    "requirements.txt"
    # systemd unit
    "wireless.service"
)
sha256sums=('SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP'
            'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP'
            'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP'
            'SKIP' 'SKIP' 'SKIP' 'SKIP' 'SKIP'
            'SKIP')

# ─── NOTE ────────────────────────────────────────────────────────────────────
# For AUR publishing replace source/sha256sums above with the GitHub tarball
# variant and run: makepkg --geninteg >> PKGBUILD (after setting the URL).
# ──────────────────────────────────────────────────────────────────────────────

prepare() {
    # When building from local files (makepkg -e), reconstruct the layout
    # that pip/setuptools expects inside $srcdir.
    local S="${srcdir}/wireless-src"
    mkdir -p \
        "${S}/wireless/parsers" \
        "${S}/wireless/generators" \
        "${S}/wireless/managers"

    cp "${srcdir}/wireless-cli"               "${S}/wireless/cli.py"
    cp "${srcdir}/pyproject.toml"             "${S}/pyproject.toml"
    cp "${srcdir}/requirements.txt"           "${S}/requirements.txt"
    cp "${srcdir}/wireless-config"            "${S}/wireless/config.py"
    cp "${srcdir}/wireless-models"            "${S}/wireless/models.py"
    cp "${srcdir}/wireless-init"              "${S}/wireless/__init__.py"
    cp "${srcdir}/wireless-parsers-init"      "${S}/wireless/parsers/__init__.py"
    cp "${srcdir}/wireless-parsers-base"      "${S}/wireless/parsers/base.py"
    cp "${srcdir}/wireless-parsers-auto"      "${S}/wireless/parsers/auto.py"
    cp "${srcdir}/wireless-parsers-vless"     "${S}/wireless/parsers/vless.py"
    cp "${srcdir}/wireless-parsers-vmess"     "${S}/wireless/parsers/vmess.py"
    cp "${srcdir}/wireless-parsers-trojan"    "${S}/wireless/parsers/trojan.py"
    cp "${srcdir}/wireless-parsers-hysteria2" "${S}/wireless/parsers/hysteria2.py"
    cp "${srcdir}/wireless-generators-init"   "${S}/wireless/generators/__init__.py"
    cp "${srcdir}/wireless-generators-singbox" "${S}/wireless/generators/singbox.py"
    cp "${srcdir}/wireless-generators-wireguard" "${S}/wireless/generators/wireguard.py"
    cp "${srcdir}/wireless-managers-init"     "${S}/wireless/managers/__init__.py"
    cp "${srcdir}/wireless-managers-wg"       "${S}/wireless/managers/wireguard.py"
    cp "${srcdir}/wireless-managers-sb"       "${S}/wireless/managers/singbox.py"
    cp "${srcdir}/wireless-managers-rt"       "${S}/wireless/managers/routing.py"
}

build() {
    cd "${srcdir}/wireless-src"
    python -m build --wheel --no-isolation
}
check() {
    cd "${srcdir}/wireless-src"
    python -m py_compile \
        wireless/parsers/vless.py \
        wireless/parsers/vmess.py \
        wireless/parsers/trojan.py \
        wireless/parsers/hysteria2.py \
        wireless/parsers/auto.py \
        wireless/generators/singbox.py \
        wireless/generators/wireguard.py \
        wireless/models.py \
        wireless/cli.py
    python -c "from wireless.cli import main"
}

package() {
    cd "${srcdir}/wireless-src"

    # Install Python package into /usr
    python -m installer --destdir="$pkgdir" dist/*.whl

    # /etc/wireless directory skeleton
    install -dm700 "${pkgdir}/etc/wireless"
    install -dm700 "${pkgdir}/etc/wireless/wireguard"
    install -dm755 "${pkgdir}/etc/wireless/singbox"

    # systemd service unit
    install -Dm644 "${srcdir}/wireless.service" \
        "${pkgdir}/usr/lib/systemd/system/wireless.service"

    # License
    install -Dm644 /dev/null "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE"
    cat > "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE" << 'EOF'
MIT License — see project repository for full text.
EOF

    # Docs
    if [[ -f "${srcdir}/README.md" ]]; then
        install -Dm644 "${srcdir}/README.md" \
            "${pkgdir}/usr/share/doc/${pkgname}/README.md"
    fi
}
