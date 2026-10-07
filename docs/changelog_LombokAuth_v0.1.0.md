# Changelog LombokAuth (ringkasan)

Entri terbaru di depan. Rincian ada di `CHANGELOG.md`.

## 0.1.0 - 2026-10-07

### Added
- JWT HS256, hash PBKDF2 PHC, HOTP/TOTP, RBAC.
- Port Rust `no_std + alloc` dan port TypeScript.
- Vector 381 kasus; runner di kedua port; fuzz, uji mutasi.

### Security
- Hanya HS256; `none` dan algoritma lain ditolak; tanda tangan diperiksa sebelum klaim.
- Perbandingan rahasia waktu-konstan; batas iterasi PBKDF2 1000..10000000.
- Aturan tolak selalu menang; rantai pewarisan dibatasi tanpa risiko stack overflow.
