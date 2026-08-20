#!/usr/bin/env bash
#
# Install netwatch on a Raspberry Pi (or any systemd Linux box).
#
# Run this ON the Pi, from the repository root, after building:
#     cargo build --release
#     sudo ./deploy/install.sh
#
# Re-running is safe: it upgrades the binary and leaves your config and
# database alone.

set -euo pipefail

BIN_SRC="target/release/netwatch"
BIN_DEST="/usr/local/bin/netwatch"
CONF_DIR="/etc/netwatch"
CONF="$CONF_DIR/config.toml"
STATE_DIR="/var/lib/netwatch"
UNIT="/etc/systemd/system/netwatch.service"
SVC_USER="netwatch"

die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }

[[ $EUID -eq 0 ]] || die "run with sudo"
[[ -f $BIN_SRC ]] || die "$BIN_SRC not found — run 'cargo build --release' first"
command -v systemctl >/dev/null || die "this script expects systemd"

# --- port 53 availability ---------------------------------------------------
# systemd-resolved's stub listener squats on 127.0.0.53:53 and, on some images,
# on the LAN address too. netwatch cannot bind 0.0.0.0:53 while it does.
if systemctl is-active --quiet systemd-resolved; then
  if ! grep -qs '^DNSStubListener=no' /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/*.conf 2>/dev/null; then
    warn "systemd-resolved is running and may hold port 53."
    warn "If netwatch fails to bind, free the port with:"
    warn "    sudo mkdir -p /etc/systemd/resolved.conf.d"
    warn "    printf '[Resolve]\\nDNSStubListener=no\\n' | sudo tee /etc/systemd/resolved.conf.d/netwatch.conf"
    warn "    sudo systemctl restart systemd-resolved"
  fi
fi

# --- service account --------------------------------------------------------
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
  info "creating system user $SVC_USER"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
fi

# --- binary -----------------------------------------------------------------
info "installing $BIN_DEST"
# install(1) writes to a temp file and renames, so a running service keeps its
# current inode instead of being corrupted mid-execution.
install -m 0755 "$BIN_SRC" "$BIN_DEST"

# --- config -----------------------------------------------------------------
install -d -m 0750 -o root -g "$SVC_USER" "$CONF_DIR"
if [[ -f $CONF ]]; then
  info "keeping existing $CONF"
  install -m 0644 config.example.toml "$CONF_DIR/config.example.toml"
else
  info "installing default $CONF"
  # The config may hold web.admin_token, so it is readable by the service
  # account and root, and by nobody else.
  install -m 0640 -o root -g "$SVC_USER" config.example.toml "$CONF"
fi

# Tighten an existing config too: earlier versions installed it world-readable
# and it can now contain a secret.
if [[ -f $CONF ]]; then
  chown root:"$SVC_USER" "$CONF"
  chmod 0640 "$CONF"
fi

# --- state ------------------------------------------------------------------
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$STATE_DIR"
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$STATE_DIR/lists"

# --- config check -----------------------------------------------------------
# Before touching a running service, prove it would come back up. Restarting
# into a config netwatch cannot parse leaves the whole LAN without DNS, and
# systemd cannot fix that by retrying — it just retries the same broken file.
# A stale-but-serving netwatch beats a stopped one every time.
info "validating $CONF"
if ! "$BIN_DEST" --config "$CONF" --check-config; then
  die "config is not valid — leaving the running service untouched. Fix the above, then re-run."
fi

# --- unit -------------------------------------------------------------------
info "installing $UNIT"
install -m 0644 deploy/netwatch.service "$UNIT"
systemctl daemon-reload
systemctl enable netwatch >/dev/null

if systemctl is-active --quiet netwatch; then
  info "restarting netwatch"
  systemctl restart netwatch
else
  info "starting netwatch"
  systemctl start netwatch
fi

sleep 2
if ! systemctl is-active --quiet netwatch; then
  warn "netwatch did not stay running. Recent log:"
  journalctl -u netwatch -n 30 --no-pager || true
  exit 1
fi

# Best-effort LAN address for the closing instructions.
IP=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || hostname -I 2>/dev/null | awk '{print $1}')
IP=${IP:-<pi-ip>}

cat <<EOF

$(info "netwatch is running")

  Dashboard   http://localhost:8080  (on the Pi; see below for remote access)
  Logs        journalctl -u netwatch -f
  Config      $CONF

After editing the config, check it before restarting — an unparseable config
takes DNS down for every device on the network, and systemd cannot recover it:

      sudo netwatch --config $CONF --check-config && sudo systemctl restart netwatch

The dashboard listens on loopback only by default, because it can change block
rules and flush the DNS cache. To reach it from another machine, either:

  Tunnel over SSH (nothing to configure, nothing exposed)
      ssh -L 8080:localhost:8080 ${SUDO_USER:-$(whoami)}@$IP
      then browse to http://localhost:8080

  Or bind it to the LAN, which requires a token:
      TOKEN=\$(openssl rand -hex 32)
      sudo sed -i "s|^listen = \"127.0.0.1:8080\"|listen = \"0.0.0.0:8080\"|" $CONF
      echo "admin_token = \"\$TOKEN\"" | sudo tee -a $CONF   # under [web]
      sudo systemctl restart netwatch
      # netwatch refuses to start if it is off-loopback without a token.

Nothing is being monitored yet — devices have to be told to use the Pi for DNS.
Pick one:

  Whole network (recommended)
      In your router's DHCP/LAN settings, set the DNS server to $IP.
      Reboot devices, or wait for their DHCP leases to renew.

  A single device, to try it out first
      Set its DNS server manually to $IP.

Verify it is answering:
      nslookup github.com $IP

EOF
