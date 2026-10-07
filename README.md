# LombokAuth

[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)](LICENSE-APACHE)

Inti autentikasi tanpa dependensi: **JWT HS256** dengan verifikasi klaim yang ketat, **hash kata sandi PBKDF2-SHA256** dalam format PHC, **HOTP/TOTP** untuk aplikasi authenticator, dan **RBAC** dengan wildcard, pewarisan peran, dan aturan tolak. Fungsi murni: salt, secret, dan waktu dipasok pemanggil. Hasilnya identik di setiap port.

Part of the [Lombok Ecosystem](https://github.com/codinglombok).

## Mengapa library ini?

Kesalahan autentikasi yang paling sering bukan pada kriptografinya, tetapi pada aturan di sekitarnya: menerima `alg: none`, lupa memeriksa `exp`, membandingkan tanda tangan dengan `==`, atau menyimpan hash kata sandi dengan iterasi yang terlalu kecil. Setiap bahasa memiliki pustaka dengan bawaan yang berbeda. LombokAuth menetapkan aturan itu secara normatif, menolak bentuk yang meragukan secara eksplisit, dan membuktikannya dengan vector bersama, termasuk vector RFC 4226, RFC 6238, dan RFC 4648.

Skenario pemakaian:

- **Layanan web dan API**: token akses HS256 berumur pendek dengan pemeriksaan `iss`, `aud`, `exp`, `nbf`.
- **Pendaftaran dan login**: hash PBKDF2 berformat PHC dan deteksi kapan hash perlu diperbarui.
- **Autentikasi dua faktor**: TOTP kompatibel dengan aplikasi authenticator, termasuk URI `otpauth://` untuk kode QR.
- **Otorisasi**: kebijakan RBAC sebagai data JSON yang dapat diperiksa dan dibagi antar layanan dalam bahasa berbeda.
- **Serverless, edge, dan perangkat tertanam**: inti Rust `no_std + alloc` tanpa dependensi.

Contoh dependen lain di ekosistem Lombok dicantumkan di `docs/map_LombokAuth_v0.1.0.md`.

## Fitur

Setiap fitur di bawah ini dicakup vector di `vectors/` dan test TypeScript.

- `signJwt`, `verifyJwt`, `decodeJwtUnverified`: hanya HS256; `none` dan algoritma lain ditolak; `crit` ditolak; base64url kanonik; `exp` wajib secara bawaan; `leeway`, `issuer`, `audience`.
- `hashPassword`, `verifyPassword`, `needsRehash`: PBKDF2-HMAC-SHA256, bawaan 600000 iterasi, salt paling sedikit 16 byte, format `$pbkdf2-sha256$i=...$salt$hash`.
- `hotp`, `totp`, `verifyTotp`, `otpauthUri`, `base32Encode`, `base32Decode`: SHA1 dan SHA256, 6 sampai 8 digit, jendela verifikasi dengan offset langkah untuk deteksi replay.
- `can`, `effectivePermissions`, `validatePolicy`: izin bertitik dengan `*`, aturan `!tolak` yang selalu menang, pewarisan dengan deteksi siklus dan batas rantai 64.
- `hashPasswordRandom` (TypeScript) memakai `crypto.getRandomValues`.

## Instalasi

Belum terbit di registry. Setelah rilis pertama:

```bash
npm install lombokauth      # TypeScript / JavaScript
cargo add lombokauth        # Rust
```

## Quick Start

### TypeScript

```ts
import { signJwt, verifyJwt, hashPasswordRandom, verifyPassword, totp, can } from "lombokauth";

const secret = process.env.JWT_SECRET!;                          // paling sedikit 32 byte
const now = Math.floor(Date.now() / 1000);
const token = signJwt({ sub: "user-1", iss: "https://id.example.com", exp: now + 900 }, secret);
const { claims } = verifyJwt(token, secret, { now, issuer: "https://id.example.com" });

const stored = hashPasswordRandom("correct horse battery staple");
verifyPassword("correct horse battery staple", stored);           // true

totp("12345678901234567890", 59);                                 // "287082"

const policy = { roles: { editor: { permissions: ["posts.*", "!posts.delete"] } } };
can(policy, ["editor"], "posts.delete");                          // false
```

### Rust

```rust
use lombokauth::{hash_password, sign_jwt, totp, verify_jwt, verify_password, parse_json, TotpOptions, VerifyOptions};

let secret = b"a-string-secret-at-least-256-bits-long";
let claims = parse_json(r#"{"sub":"user-1","exp":1700000600}"#).unwrap();
let token = sign_jwt(&claims, secret, None).unwrap();
let (_, c) = verify_jwt(&token, secret, &VerifyOptions::at(1700000000.0)).unwrap();
let phc = hash_password("correct horse", &[7u8; 16], 1000).unwrap();
assert!(verify_password("correct horse", &phc).unwrap());
assert_eq!(totp(b"12345678901234567890", 59, &TotpOptions::default()).unwrap(), "287082");
```

## Status port

| Port | Status | Bukti |
|---|---|---|
| Rust (`no_std + alloc`) | YA, lulus vector | `rust/tests/vectors.rs` menjalankan seluruh vector; uji rantai pewarisan 200000 peran; build `thumbv7em-none-eabi` |
| TypeScript | YA, lulus vector | `typescript/test/vectors.test.ts` menjalankan seluruh vector; kripto dibandingkan dengan `node:crypto`; fuzz token termutasi |
| Python, Go, PHP, Java, Kotlin, C#, C/C++, Swift, Perl | BELUM | Tidak ada kode; direncanakan setelah kontrak stabil (lihat `docs/development_ide_LombokAuth_v0.1.0.md`) |

Vector: 381 kasus (211 golden berekspektasi tulis tangan, dari RFC, atau dibangun dengan `node:crypto`; 170 regresi hasil pembangkit).

## Standar yang diimplementasikan

RFC 7519 (JWT), RFC 7515 (JWS compact), RFC 7518 bagian 3.2 (HS256, panjang kunci), RFC 8725 (praktik terbaik JWT: allow-list algoritma), RFC 8018 (PBKDF2), PHC string format, RFC 4226 (HOTP), RFC 6238 (TOTP), RFC 4648 (base32, base64url), Key Uri Format (`otpauth://`). Lihat `docs/SPEC_LombokAuth_v0.1.0.md`.

## Batasan yang diketahui

- JWT hanya HS256; tidak ada RS256, ES256, EdDSA, JWE, atau JWKS.
- PBKDF2 dipilih karena dapat diimplementasikan tanpa dependensi di semua port; Argon2id lebih kuat terhadap serangan GPU dan direncanakan sebagai opsi.
- Implementasi kripto belum diaudit pihak ketiga.
- TOTP tidak menyimpan langkah yang sudah dipakai; pencegahan replay memakai offset yang dikembalikan `verifyTotp` dan penyimpanan milik aplikasi.
- Port Rust tidak memiliki sumber keacakan; salt dipasok pemanggil.
- Hanya Rust dan TypeScript yang memiliki kode. Fuzz bersifat pseudo-fuzz, belum `cargo-fuzz`.

## Ekosistem Lombok

LombokAuth tidak bergantung pada library Lombok lain (L0). Library lain dapat memakainya secara opsional; daftar dependen ada di `docs/map_LombokAuth_v0.1.0.md`.

## Contributing

Lihat [CONTRIBUTING.md](CONTRIBUTING.md). Untuk melaporkan kerentanan lihat [SECURITY.md](SECURITY.md).

## Lisensi

`Apache-2.0 OR MIT`. Lihat [LICENSE-APACHE](LICENSE-APACHE) dan [LICENSE-MIT](LICENSE-MIT).
