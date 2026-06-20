# SatsetOps Agent

Binary Go yang dipasang di VPS user untuk [SatsetOps](https://github.com/azmifauzan/satsetops). Ringan (<20MB memory target), tanpa UI/panel.

## Peran

Agent = **dumb executor**. Semua logic & keputusan ada di SatsetOps Web; agent tidak pernah bertindak otonom.

- **Executor** — jalankan instruksi dari whitelist (firewall, deploy via Docker, restart container, SSL). Tidak ada jalur shell sembarangan.
- **Reporter** — kirim CPU/RAM/disk/uptime, status container, log ringkas.

## Model komunikasi

Pull-based polling: agent polling perintah dari SatsetOps API tiap N detik via HTTPS (Bearer permanent token). SatsetOps tidak pernah push/SSH ke VPS. Token bisa di-revoke dari dashboard → agent berhenti polling (respons 401).

## Status

Belum diimplementasikan. Scaffold + koneksi dimulai di Phase 0/1 — lihat [implementation plans](https://github.com/azmifauzan/satsetops/blob/main/docs/superpowers/plans/README.md).

## Build (setelah scaffold)

```bash
go test ./...
go build -o agent .
```

## Instalasi (di VPS user)

Dipasang lewat satu perintah `curl` dari dashboard SatsetOps (one-time token → otomatis ditukar jadi permanent token terenkripsi di VPS).
