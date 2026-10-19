# Dokumentasi Temuan dan Mitigasi

Istilah yang dipakai:
- **Observasi**: fakta yang terlihat di respons (contoh: header tidak ada).
- **Potensi risiko**: apa yang *bisa* terjadi bila ada kelemahan lain. Belum terbukti.
- **Kerentanan terkonfirmasi**: butuh pembuktian terpisah dan izin. **Tool ini tidak pernah menghasilkan temuan jenis ini.**

Semua "bukti" di bawah adalah nilai header dari respons, bukan data sensitif.

## 1. Content-Security-Policy (CSP)
| Aspek | Penjelasan |
|---|---|
| Pemicu MISSING | Header tidak ada. |
| Pemicu REVIEW | Tidak ada `default-src`/`script-src`; `'unsafe-inline'` tanpa nonce/hash; `'unsafe-eval'`; sumber terlalu luas (`*`, `http:`, `https:`, `data:`). |
| Bukti aman | Nilai header (dipotong 200 karakter). |
| Potensi risiko | Bila ada celah XSS, eksploitasinya lebih mudah tanpa CSP yang ketat. |
| Dampak mungkin | Eksekusi script tak sah di browser pengguna (pencurian sesi, aksi atas nama pengguna) **jika** celah XSS ada. |
| Mitigasi | Mulai dari `default-src 'self'`; pakai nonce/hash; uji dengan `Content-Security-Policy-Report-Only` dulu. |
| Verifikasi ulang | Jalankan ulang tool; cek console browser untuk pelanggaran CSP. |
| Keterbatasan | Tool tidak mem-parse seluruh semantik CSP. |

## 2. Strict-Transport-Security (HSTS)
| Aspek | Penjelasan |
|---|---|
| Pemicu MISSING | URL akhir HTTPS tetapi header tidak ada. |
| Pemicu REVIEW | URL akhir HTTP (tidak dapat dinilai); `max-age` tidak ada atau di bawah 15552000 detik (180 hari). |
| Bukti aman | Nilai header, skema URL akhir. |
| Potensi risiko | Pengguna lebih mudah terkena downgrade/SSL stripping pada jaringan yang tidak tepercaya. |
| Dampak mungkin | Penyadapan atau modifikasi lalu lintas pada koneksi HTTP pertama. |
| Mitigasi | Kirim HSTS di respons HTTPS dengan `max-age` minimal 180 hari; `includeSubDomains` hanya setelah semua subdomain mendukung HTTPS. |
| Verifikasi ulang | Uji URL HTTPS dan pastikan nilai `max-age`. |
| Keterbatasan | Status preload tidak diperiksa. |

## 3. X-Content-Type-Options
| Aspek | Penjelasan |
|---|---|
| Pemicu | MISSING bila tidak ada; REVIEW bila nilainya bukan `nosniff`. |
| Potensi risiko | Browser dapat menebak tipe konten dan menafsirkan file sebagai tipe yang bisa dieksekusi dalam skenario tertentu. |
| Dampak mungkin | Konten unggahan/refleksi diperlakukan sebagai script bila ada kelemahan lain. |
| Mitigasi | `X-Content-Type-Options: nosniff` dan `Content-Type` yang benar di semua respons. |
| Verifikasi ulang | Jalankan ulang; nilai harus tepat `nosniff`. |
| Keterbatasan | Hanya URL yang diperiksa; rute lain bisa berbeda. |

## 4. X-Frame-Options
| Aspek | Penjelasan |
|---|---|
| Pemicu MISSING | Tidak ada XFO dan tidak ada CSP `frame-ancestors`. |
| Pemicu REVIEW | XFO tidak ada tetapi CSP `frame-ancestors` ada; atau nilai usang/non-standar (mis. `ALLOW-FROM`). |
| Potensi risiko | Halaman dapat dibingkai oleh situs lain untuk clickjacking. |
| Dampak mungkin | Pengguna terpancing mengklik elemen tersembunyi pada halaman yang sedang login. Dampak nyata bergantung pada fungsi halaman. |
| Mitigasi | CSP `frame-ancestors` (utama); opsional XFO `DENY` atau `SAMEORIGIN`. |
| Verifikasi ulang | Jalankan ulang; opsional uji framing dari file HTML lokal milik sendiri. |
| Keterbatasan | Tool tidak menilai apakah framing benar-benar berbahaya untuk halaman itu. |

## 5. Referrer-Policy
| Aspek | Penjelasan |
|---|---|
| Pemicu MISSING | Header tidak ada (browser memakai default). |
| Pemicu REVIEW | Tidak ada token dikenal; kebijakan efektif (token valid terakhir) adalah `unsafe-url`, `no-referrer-when-downgrade`, atau `origin-when-cross-origin`. |
| Potensi risiko | URL lengkap, yang mungkin memuat ID atau token, bisa terkirim ke pihak ketiga. |
| Dampak mungkin | Kebocoran informasi lewat header Referer. |
| Mitigasi | `strict-origin-when-cross-origin` atau lebih ketat; jangan menaruh rahasia di URL. |
| Verifikasi ulang | Jalankan ulang; cek header Referer di dev tools browser. |
| Keterbatasan | Kebijakan dari tag `<meta>` atau atribut elemen tidak terlihat. |

## 6. Permissions-Policy
| Aspek | Penjelasan |
|---|---|
| Pemicu | MISSING bila tidak ada; REVIEW bila kosong. |
| Potensi risiko | Konten pihak ketiga tersemat bisa meminta fitur browser yang tidak dibutuhkan situs. |
| Dampak mungkin | Permintaan izin kamera, mikrofon, atau lokasi lewat iframe. |
| Mitigasi | Nonaktifkan fitur tak terpakai, mis. `camera=(), microphone=(), geolocation=()`. |
| Verifikasi ulang | Jalankan ulang dan tinjau daftar direktif. |
| Keterbatasan | Isi direktif tidak divalidasi; dukungan browser berbeda-beda. |

## Catatan tambahan (bukan header)
- **Redirect HTTPS ke HTTP**: ditampilkan sebagai catatan di laporan, karena dapat menurunkan perlindungan koneksi.
- **Redirect ke alamat internal diblokir**: bukan temuan terhadap target, melainkan pengaman tool. Jika muncul, observasinya adalah target publik mengarahkan klien ke alamat non-publik; itu patut ditinjau manual oleh pemilik situs (potensi open redirect atau konfigurasi proxy yang keliru), tetapi belum merupakan kerentanan terkonfirmasi.
- **Status 4xx/5xx**: ditandai karena header di halaman error bisa berbeda dari halaman normal.
