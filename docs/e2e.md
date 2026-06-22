# Phase 1 E2E Smoke

## Prerequisites

- SatSetOps Web is reachable over HTTPS.
- Linux VM uses systemd and has `curl` installed.
- Agent release contains `satsetopsagent-linux-amd64` and/or `satsetopsagent-linux-arm64`.

## Procedure

1. Start the web dependencies and application from `satsetopsweb/` with `docker compose up -d` and `composer run dev`.
2. Open **VPS**, choose **Tambah VPS**, enter a name, and copy the generated install command.
3. Run the command on a fresh VM. Confirm `systemctl status satsetops-agent` is active and the dashboard status changes to `online`.
4. Confirm CPU, RAM, disk, and uptime appear after at most one metrics interval (30 seconds by default).
5. Confirm the initial `scan_vps` command is `done` in the database and its JSON result is stored on the server record.
6. Choose **Revoke token**. Within one poll interval (10 seconds by default), confirm `journalctl -u satsetops-agent` contains `token revoked, stopping` and the unit is inactive rather than restarting.
7. Confirm `audit_logs` contains `agent.connected` and `token.revoked` for the server.

The installer temporarily stores the one-time token in `/etc/satsetops/agent.env` so a failed first registration can retry. After a successful exchange, the agent removes that line and keeps only the encrypted permanent token in `/etc/satsetops/token.enc` with mode `0600`.

## Run log (2026-06-22)

Executed against a real empty VPS (Ubuntu 24.04 x86_64). Web ran locally (no public deploy yet); VPS→web reachability was provided by an SSH reverse tunnel (`ssh -R 8000:127.0.0.1:8000`) instead of a public HTTPS endpoint, so steps 1-2 of `install.sh` (GitHub release download, HTTPS-only check) were bypassed by copying a locally built `GOOS=linux GOARCH=amd64` binary directly — that gap is a Phase 3 (deploy) concern, not Phase 1 logic.

Result: register → online, `scan_vps` → done, 2 metrics rows within ~30s, revoke → clean stop (`token revoked, stopping`, exit 0, no restart-loop) inside one poll interval, `audit_logs` has both `agent.connected` and `token.revoked`. Memory ~1.7MB. All test data and the systemd unit were removed from the VPS afterward.
