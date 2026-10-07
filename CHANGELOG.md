# Changelog

Semua perubahan penting dicatat di sini. Format mengikuti [Keep a Changelog](https://keepachangelog.com/); entri terbaru di depan. Versi mengikuti [SemVer](https://semver.org/).

## [0.1.0] - 2026-10-07

### Added
- JWT HS256: `signJwt`, `verifyJwt` (allow-list algoritma, penolakan `crit`, base64url kanonik, `exp` wajib, `nbf`, `iss`, `aud`, `leeway`), `decodeJwtUnverified`.
- Hash kata sandi PBKDF2-HMAC-SHA256 berformat PHC: `hashPassword`, `verifyPassword`, `needsRehash`.
- HOTP dan TOTP (SHA1, SHA256), `verifyTotp` dengan offset langkah, `otpauthUri`, base32 RFC 4648.
- RBAC: pola izin dengan `*`, aturan tolak, pewarisan dengan deteksi siklus dan batas rantai 64.
- Port Rust (`no_std + alloc`, tanpa dependensi) dan port TypeScript (tanpa dependensi runtime).
- Vector bersama 381 kasus (211 golden berekspektasi tulis tangan, dari RFC, atau dibangun dengan node:crypto, 170 regresi hasil pembangkit), dijalankan oleh runner Rust dan TypeScript.
- Pseudo-fuzz dan skrip uji mutasi (25 mutan).

### Security
- Hanya HS256; `none` dan algoritma lain ditolak; tanda tangan diperiksa sebelum klaim.
- Perbandingan rahasia waktu-konstan; batas iterasi PBKDF2 1000..10000000.
- Aturan tolak selalu menang; rantai pewarisan dibatasi tanpa risiko stack overflow.
