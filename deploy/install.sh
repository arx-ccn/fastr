#!/bin/sh
# fastr install script
# Detects your platform and init system, then installs the binary and service.
#
# Usage:
#   sudo ./deploy/install.sh [binary_path]
#
# binary_path defaults to ./target/release/fastr

set -e

BINARY="${1:-./target/release/fastr}"
INSTALL_BIN="/usr/local/bin/fastr"

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

info()  { printf '  \033[32m=>\033[0m %s\n' "$*"; }
warn()  { printf '  \033[33m!!\033[0m %s\n' "$*"; }
die()   { printf '  \033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

check_root() {
    [ "$(id -u)" = "0" ] || die "Run as root (sudo ./deploy/install.sh)"
}

install_binary() {
    [ -f "$BINARY" ] || die "Binary not found: $BINARY  (run: cargo build --release)"
    info "Installing binary to $INSTALL_BIN"
    install -m 755 "$BINARY" "$INSTALL_BIN"
}

# ----------------------------------------------------------------------------
# Platform detection
# ----------------------------------------------------------------------------

OS="$(uname -s)"

detect_init() {
    if [ "$OS" = "Darwin" ]; then
        echo "launchd"
    elif [ "$OS" = "FreeBSD" ]; then
        echo "rc.d"
    elif [ -d /run/systemd/private ] || command -v systemctl >/dev/null 2>&1; then
        echo "systemd"
    elif command -v rc-update >/dev/null 2>&1; then
        echo "openrc"
    elif command -v sv >/dev/null 2>&1; then
        echo "runit"
    else
        echo "unknown"
    fi
}

INIT="$(detect_init)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

info "Detected: OS=$OS init=$INIT"

# ----------------------------------------------------------------------------
# Init-specific install
# ----------------------------------------------------------------------------

install_systemd() {
    id fastr >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin fastr
    install -d -o fastr -g fastr /var/lib/fastr/data
    install -m 644 "$SCRIPT_DIR/fastr.service" /etc/systemd/system/fastr.service
    systemctl daemon-reload
    systemctl enable fastr
    info "Installed systemd service. Start with: systemctl start fastr"
}

install_openrc() {
    id fastr >/dev/null 2>&1 || adduser -S -D -H -s /sbin/nologin fastr
    install -d -o fastr -g fastr /var/lib/fastr/data
    install -d -o fastr -g fastr /var/log/fastr
    install -m 755 "$SCRIPT_DIR/fastr.openrc" /etc/init.d/fastr
    rc-update add fastr default
    info "Installed OpenRC service. Start with: rc-service fastr start"
}

install_runit() {
    id fastr >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin fastr
    install -d -o fastr -g fastr /var/lib/fastr/data
    install -d /etc/sv/fastr
    install -m 755 "$SCRIPT_DIR/fastr.runit" /etc/sv/fastr/run
    if [ -d /var/service ]; then
        ln -sf /etc/sv/fastr /var/service/fastr
        info "Linked /var/service/fastr. sv will pick it up shortly."
    else
        warn "/var/service not found. Link manually: ln -s /etc/sv/fastr /var/service/fastr"
    fi
}

install_rcd() {
    pw useradd fastr -s /usr/sbin/nologin -d /nonexistent -c "fastr nostr relay" 2>/dev/null || true
    install -d -o fastr -g fastr /var/db/fastr/data
    install -m 555 "$SCRIPT_DIR/fastr.rc" /usr/local/etc/rc.d/fastr
    sysrc fastr_enable="YES"
    info "Installed rc.d service. Start with: service fastr start"
}

install_launchd() {
    DATA_DIR="/usr/local/var/fastr/data"
    LOG_DIR="/usr/local/var/log"
    dscl . -read /Users/_fastr >/dev/null 2>&1 || \
        dscl . -create /Users/_fastr \
               UserShell /usr/bin/false \
               NFSHomeDirectory /var/empty \
               UniqueID "$(python3 -c 'import random; print(random.randint(300,399))')" \
               PrimaryGroupID 20
    install -d "$DATA_DIR"
    chown _fastr "$DATA_DIR"
    install -d "$LOG_DIR"
    install -m 644 "$SCRIPT_DIR/fastr.plist" /Library/LaunchDaemons/com.arx-ccn.fastr.plist
    launchctl load -w /Library/LaunchDaemons/com.arx-ccn.fastr.plist
    info "Installed LaunchDaemon. fastr will start now and at boot."
}

# ----------------------------------------------------------------------------
# Run
# ----------------------------------------------------------------------------

check_root
install_binary

case "$INIT" in
    systemd) install_systemd ;;
    openrc)  install_openrc  ;;
    runit)   install_runit   ;;
    rc.d)    install_rcd     ;;
    launchd) install_launchd ;;
    *)
        warn "Could not detect init system."
        warn "Binary installed to $INSTALL_BIN."
        warn "Install a service file from deploy/ manually."
        ;;
esac

info "Done. fastr is installed."
