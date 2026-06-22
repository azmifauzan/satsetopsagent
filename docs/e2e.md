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

# Phase 2 E2E Smoke

## Procedure

1. Run a clean `scan_vps` to completion (see Phase 1 procedure above).
2. Confirm `HardeningOrchestrator` enqueues `harden_firewall`, `ssh_harden`, `install_crowdsec`, `sysupdate` (plus `docker_harden` only if the scan reported `docker: true`) as `pending` commands.
3. Let the agent poll and execute all of them; confirm each transitions to `done`.
4. On the VM: `ufw status verbose` (default deny incoming, 22/80/443 allow), `sshd -T` (`permitemptypasswords no`, `maxauthtries 4`, `x11forwarding no`; `permitrootlogin`/`passwordauthentication` untouched), `systemctl is-active crowdsec` + `cscli bouncers list`, `systemctl is-enabled unattended-upgrades`.
5. Confirm password SSH login still works after hardening (the whole point of the ssh_harden product decision — see Phase 2 plan item 7).
6. Re-queue the same 4 commands and re-run them once more; confirm identical `done` results (idempotency).

## Run log (2026-06-22)

Executed against the same VPS as the Phase 1 run (43.129.58.8, Ubuntu, SSH reverse tunnel). Found and fixed 5 real gaps that `FakeRunner`-based unit/Feature tests could not catch — see Phase 2 plan's "Verifikasi & Gap Fix" items 8-12 for full detail:

1. `HardeningOrchestrator` sent `'payload' => []`, which PHP serializes as a JSON array; Go's `map[string]any` unmarshal failed on it and silently broke the entire `GET /commands` poll decode. Fixed by dropping the `payload` key.
2. Commands already marked `sent` by a failed poll have no automatic redelivery — required a manual DB reset to `pending` during this test.
3. `install.sh`'s systemd unit used `ProtectSystem=strict`, then `ProtectSystem=true` — both made `/usr` (or more) read-only, breaking every `apt-get install` and config write the hardening executors need. Removed `ProtectSystem`/`ProtectHome` entirely; kept `NoNewPrivileges`/`PrivateTmp`.
4. `apt-get install` invoked without `DEBIAN_FRONTEND=noninteractive` fails under systemd (no controlling TTY). Fixed in `crowdsec.go` and `sysupdate.go`.
5. `docker_harden` was enqueued unconditionally; the test VM has no Docker, so it failed `Unit docker.service not found`. Fixed by gating on the scan's `docker` flag.

After all fixes: full hardening batch ran clean end-to-end (`harden_firewall`, `ssh_harden`, `install_crowdsec`, `sysupdate` all `done`; `docker_harden` correctly skipped). Re-queued and re-ran the same 4 commands a second time — identical clean `done` results, confirming idempotency. Verified live on the VM: UFW active with default-deny + 22/80/443 open, `sshd -T` shows the new hardening flags with `permitrootlogin yes`/`passwordauthentication yes` untouched, password SSH login re-tested and still works, CrowdSec active with a registered bouncer, unattended-upgrades enabled. All test data, the systemd unit, and the agent binary were removed from the VPS afterward.
