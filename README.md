# SatsetOps Agent

Binary Go yang dipasang di VPS user untuk [SatsetOps](https://github.com/azmifauzan/satsetops). Ringan (<20MB memory target), tanpa UI/panel.

## Peran

Agent = **dumb executor**. Semua logic & keputusan ada di SatsetOps Web; agent tidak pernah bertindak otonom.

- **Executor** — jalankan instruksi dari whitelist (firewall, deploy via Docker, restart container, SSL). Tidak ada jalur shell sembarangan.
- **Reporter** — kirim CPU/RAM/disk/uptime, status container, log ringkas.

## Model komunikasi

Pull-based polling: agent polling perintah dari SatsetOps API tiap N detik via HTTPS (Bearer permanent token). SatsetOps tidak pernah push/SSH ke VPS. Token bisa di-revoke dari dashboard → agent berhenti polling (respons 401).

## Status

Phase 1 tersedia: registrasi token sekali pakai, penyimpanan permanent token terenkripsi, polling command whitelist, pelaporan metrics, dan berhenti saat token di-revoke. Diverifikasi end-to-end terhadap VPS nyata pada 2026-06-22 (lihat [docs/e2e.md](docs/e2e.md)).

## Build

```bash
go test ./...
go build -o agent .
```

Memerlukan Go 1.24 atau lebih baru.

## Konfigurasi

| Environment | Default | Fungsi |
|---|---|---|
| `SATSETOPS_URL` | `https://app.satsetops.id` | Base URL control plane HTTPS |
| `SATSETOPS_TOKEN` | - | One-time token untuk registrasi pertama |
| `SATSETOPS_TOKEN_PATH` | `/etc/satsetops/token.enc` | Lokasi permanent token terenkripsi |
| `SATSETOPS_POLL_INTERVAL` | `10s` | Interval polling command |
| `SATSETOPS_METRICS_INTERVAL` | `30s` | Interval pelaporan metrics |

## Instalasi (di VPS user)

Dipasang lewat satu perintah `curl` dari dashboard SatsetOps. One-time token otomatis ditukar menjadi permanent token terenkripsi di VPS dan dihapus dari environment file setelah registrasi berhasil.
