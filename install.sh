#!/bin/sh
set -eu

fail() {
    printf 'satsetops install: %s\n' "$1" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail "run through sudo"
[ -n "${SATSETOPS_TOKEN:-}" ] || fail "SATSETOPS_TOKEN is required"

case "$SATSETOPS_TOKEN" in
    *[!A-Za-z0-9]*) fail "SATSETOPS_TOKEN has an invalid format" ;;
esac

SATSETOPS_URL="${SATSETOPS_URL:-https://app.satsetops.id}"
case "$SATSETOPS_URL" in
    https://*) ;;
    *) fail "SATSETOPS_URL must use HTTPS" ;;
esac

case "$(uname -m)" in
    x86_64) architecture="amd64" ;;
    aarch64 | arm64) architecture="arm64" ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
esac

download_base="${SATSETOPS_DOWNLOAD_BASE_URL:-https://github.com/azmifauzan/satsetopsagent/releases/latest/download}"
temporary="$(mktemp)"
trap 'rm -f "$temporary"' EXIT INT TERM

curl -fsSL "${download_base}/satsetopsagent-linux-${architecture}" -o "$temporary"
install -m 0755 "$temporary" /usr/local/bin/satsetopsagent
install -d -m 0700 /etc/satsetops

umask 077
printf 'SATSETOPS_URL=%s\nSATSETOPS_TOKEN=%s\n' "$SATSETOPS_URL" "$SATSETOPS_TOKEN" \
    > /etc/satsetops/agent.env

cat > /etc/systemd/system/satsetops-agent.service <<'UNIT'
[Unit]
Description=SatSetOps VPS Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/satsetops/agent.env
ExecStart=/usr/local/bin/satsetopsagent
Restart=on-failure
RestartSec=10
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/satsetops
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable satsetops-agent.service
systemctl restart satsetops-agent.service
printf 'SatSetOps agent installed and started.\n'
