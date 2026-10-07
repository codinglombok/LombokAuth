# Full Summary LombokAuth v0.1.0

## Apa ini

Inti autentikasi tanpa dependensi: JWT HS256 dengan verifikasi ketat, hash kata sandi PBKDF2 berformat PHC, HOTP/TOTP, dan RBAC dengan wildcard, pewarisan, dan aturan tolak.

## Mengapa dibuat

Kerentanan autentikasi umumnya berasal dari aturan di sekitar kriptografi: menerima `alg: none`, tidak memeriksa `exp`, perbandingan yang tidak waktu-konstan, atau iterasi hash yang terlalu kecil. Pustaka di setiap bahasa memiliki bawaan berbeda. Kontrak bersama menetapkan bawaan yang aman dan identik di semua port.

## Fitur utama

Lihat README (bagian Fitur). Semua fitur dicakup vector.

## Status saat ini

Kode lengkap untuk Rust dan TypeScript; lulus 381 kasus vector; belum terbit di registry; belum memenuhi aturan skor rilis (lihat `TECH_DEBT.md`).

## Contoh pemakai

Lihat README (skenario pemakaian).

## Batasan yang Diketahui

- JWT hanya HS256; tidak ada algoritma asimetris, JWE, atau JWKS.
- PBKDF2 saja; Argon2id belum tersedia.
- Kripto belum diaudit pihak ketiga.
- Pencegahan replay TOTP dan pencabutan token menjadi tanggung jawab aplikasi.
- Port Rust tidak memiliki sumber keacakan.
- Hanya dua port (Rust, TypeScript); fuzz berupa pseudo-fuzz, belum `cargo-fuzz`; belum audit pihak ketiga; coverage belum diukur.

## Info lanjut

SPEC_, API_, `development_ide_`.

## Gap vs pembanding (U6)

Perbandingan bersifat kualitatif dan berdasarkan pengetahuan umum tentang kategori library; belum diverifikasi fitur demi fitur pada 2026-10-07.

| Pembanding (kategori) | Yang dimiliki pembanding dan belum dimiliki LombokAuth | Yang ditawarkan LombokAuth |
|---|---|---|
| Pustaka JWT dan auth (jose, jsonwebtoken, PyJWT, otplib, Casbin) | Algoritma asimetris, JWKS, adapter penyimpanan, model kebijakan yang lebih kaya | Kontrak lintas bahasa dengan vector RFC; bawaan aman; inti `no_std + alloc`; tanpa dependensi |
| Penyedia identitas (Keycloak, Auth0) | OAuth2/OIDC lengkap, UI, federasi | Komponen tertanam tanpa server |
