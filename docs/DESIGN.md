# Desain Program dan Alasan Pemilihan Metode

## Arsitektur
```
cli.py -> validators.py -> fetcher.py -> rules.py -> report.py
                                 ^ local_server.py (hanya untuk uji/demo)
```
Setiap modul punya satu tanggung jawab sehingga bisa diuji terpisah. `rules.py` adalah fungsi murni (input: header + URL akhir, output: temuan), jadi tidak butuh jaringan untuk diuji.

## Keputusan desain dan alasannya
| Keputusan | Alasan |
|---|---|
| Redirect diikuti manual (`allow_redirects=False`) | Batas jumlah hop terkontrol, setiap hop divalidasi (skema harus http/https), dan penurunan HTTPS ke HTTP bisa dideteksi. |
| `stream=True` lalu `close()` | Body tidak pernah diunduh; tool hanya butuh header. |
| Pengaman redirect ke jaringan internal (`netguard.py`) | Server yang disalahgunakan bisa mengarahkan tool ke layanan internal (mis. metadata cloud `169.254.169.254`). Setiap tujuan redirect di-resolve dan diblokir bila ada alamat yang tidak global (loopback, private, link-local, CGNAT, reserved, multicast, IPv4-mapped IPv6). Gagal resolve = diblokir (fail closed). Pemeriksaan terjadi sebelum request dikirim. |
| Redirect internal diizinkan bila target awal memang internal | Penguji yang sengaja menguji lab/server lokal tetap bisa bekerja; perlindungan ditujukan untuk target awal publik. |
| Tanpa opsi `verify=False` | Mengabaikan TLS akan menyembunyikan masalah nyata dan memudahkan penyalahgunaan. |
| Tiga status (FOUND/MISSING/REVIEW) tanpa skor | Skor angka tanpa metodologi menyesatkan. Status disertai alasan tertulis. |
| HSTS lewat HTTP = REVIEW | Browser mengabaikan HSTS di HTTP, jadi "MISSING" akan keliru. |
| XFO hilang + CSP `frame-ancestors` = REVIEW | CSP `frame-ancestors` adalah mekanisme modern untuk anti-clickjacking. |
| CSP `unsafe-inline` dengan nonce/hash tidak ditandai | Browser modern mengabaikan `unsafe-inline` bila ada nonce atau hash. |
| Hanya 6 header ditampilkan, nilai dipotong 200 karakter dan karakter kontrol dibuang | Mencegah kebocoran informasi sensitif (cookie, token) dan manipulasi tampilan terminal. |
| HTML di-escape dengan `html.escape`, tanpa resource eksternal | Mencegah XSS lewat nilai header dari server dan laporan tetap berdiri sendiri. |
| `--confirm-authorized` untuk target non-lokal | Pengingat etika dan legal; penguji wajib menyatakan izin. |
| Server uji lokal dengan header decoy | Membuktikan lewat test bahwa data tak terkait tidak bocor ke laporan. |

## Strategi pengujian
79 test pytest: validasi URL (valid, tidak valid, tepi), setiap aturan header, redirect, loop redirect, timeout, koneksi ditolak, struktur JSON, escaping HTML, kode keluar CLI, tidak bocornya data decoy, dan pengaman redirect (13 jenis alamat internal, hostname yang resolve ke IP private, jawaban DNS campuran, gagal resolve, redirect publik tetap diizinkan, target awal internal). Test redirect memakai sesi palsu agar tidak butuh jaringan dan membuktikan URL internal tidak pernah di-request.

## Keterbatasan pengaman redirect
Hostname di-resolve oleh tool, lalu di-resolve lagi oleh `requests` saat koneksi. Penyerang yang mengendalikan DNS secara teori dapat memberi jawaban berbeda (DNS rebinding). Penguncian IP saat koneksi masuk daftar pengembangan.

## Hal yang sengaja tidak dilakukan
Crawling, pemindaian massal, fuzzing, eksploitasi, pengiriman data ke layanan eksternal, dan skor keamanan.
