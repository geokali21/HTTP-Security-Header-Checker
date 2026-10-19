# Panduan Penggunaan

## Instalasi di Kali Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```
Alternatif tanpa instalasi: `export PYTHONPATH=src` lalu `python -m header_checker ...`.

## Perintah dasar
```bash
header-checker --demo mixed                     # demo di server lokal (aman)
header-checker https://situs-anda.com --confirm-authorized
header-checker https://situs-anda.com --confirm-authorized --json reports/a.json --html reports/a.html
header-checker --demo weak --verbose --no-color
pytest -v
```

## Opsi
| Opsi | Fungsi |
|---|---|
| `--timeout N` | Batas waktu request (detik), default 10 |
| `--max-redirects N` | Batas redirect, 0-20, default 5 |
| `--json FILE`, `--html FILE` | Ekspor laporan |
| `--verbose` | Tampilkan penjelasan juga untuk header FOUND |
| `--no-color` | Matikan warna |
| `--confirm-authorized` | Wajib untuk target non-lokal: konfirmasi bahwa kamu pemilik atau punya izin tertulis |
| `--demo PROFIL` | Uji ke server lokal: `secure`, `weak`, `mixed` |

## Membaca hasil
- **FOUND**: header ada dan tidak ada pola lemah yang dikenali tool.
- **MISSING**: header tidak terlihat di respons. Ini observasi, bukan bukti kerentanan.
- **REVIEW**: header ada tetapi perlu ditinjau manual, atau tidak bisa dinilai dalam kondisi ini (contoh: HSTS lewat HTTP).

## Kode keluar
`0` sukses, `2` input tidak valid, `3` kegagalan jaringan (timeout, koneksi, TLS, redirect), `4` redirect ke alamat internal/private diblokir.

## Masalah umum
- `No module named header_checker`: jalankan `export PYTHONPATH=src` atau `pip install -e .`.
- `non-local target`: tambahkan `--confirm-authorized` setelah memastikan kamu berhak menguji target.
- `error [blocked]`: target publik mengarahkan redirect ke alamat internal/private (mis. `127.0.0.1`, `10.x`, `169.254.169.254`). Tool menolaknya sebelum mengirim request. Ini perilaku yang disengaja.
- `error [tls]`: sertifikat target bermasalah; tool sengaja tidak menyediakan opsi mengabaikan verifikasi TLS.
