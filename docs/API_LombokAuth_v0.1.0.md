# API LombokAuth v0.1.0

Semantik normatif ada di `SPEC_LombokAuth_v0.1.0.md`; dokumen ini hanya mendaftar antarmuka yang benar-benar diekspor.

## 1. TypeScript (paket `lombokauth`)

Stabilitas: 0.x, dapat berubah pada rilis minor. `Bytes` adalah `Uint8Array`; argumen string dibaca sebagai UTF-8.

| Simbol | Tanda tangan | Keterangan |
|---|---|---|
| `signJwt` | `(claims, secret, options?: { kid? }) => string` | Sejak 0.1.0 |
| `verifyJwt` | `(token, secret, { now, leeway?, issuer?, audience?, requireExp? }) => { header, claims }` | Melempar kode pertama yang gagal |
| `decodeJwtUnverified` | `(token) => { header, claims }` | Tanpa verifikasi |
| `hashPassword` | `(password, salt: Bytes \| hex, iterations?) => string` | PHC |
| `hashPasswordRandom` | `(password, iterations?) => string` | Salt dari `crypto.getRandomValues` |
| `verifyPassword` | `(password, phc) => boolean` | |
| `needsRehash` | `(phc, iterations?) => boolean` | |
| `hotp` | `(secret, counter, { digits?, algorithm? }?) => string` | |
| `totp` | `(secret, timeSeconds, { period?, digits?, algorithm?, t0? }?) => string` | |
| `verifyTotp` | `(secret, code, timeSeconds, { ..., window? }?) => number \| null` | Offset langkah |
| `otpauthUri` | `(secret, account, issuer, { period?, digits?, algorithm? }?) => string` | |
| `base32Encode`, `base32Decode` | RFC 4648 | |
| `validatePolicy`, `can`, `effectivePermissions` | RBAC | |
| `call` | `(fn: string, args: unknown[]) => unknown` | Titik masuk kontrak |
| `DEFAULT_ITERATIONS`, `MIN_ITERATIONS`, `MAX_ITERATIONS`, `MIN_SALT_BYTES`, `MIN_JWT_SECRET_BYTES`, `MAX_INHERITANCE` | konstanta | |
| `utf8`, `toHex`, `fromHex`, `base64url`, `base64urlDecode`, `sha256`, `hmacSha256`, `pbkdf2Sha256`, `constantTimeEqual` | primitif | Dari `crypto.ts` |
| `LombokAuthError` | `extends Error`; `code`, `messageId` | Kode: SPEC bagian 7 |

## 2. Rust (crate `lombokauth`)

Fitur: `std` (bawaan). Tanpa `std`, crate bersifat `no_std + alloc`.

| Simbol | Keterangan |
|---|---|
| `sign_jwt(&Value, &[u8], Option<&str>)`, `verify_jwt(&str, &[u8], &VerifyOptions)`, `decode_jwt_unverified(&str)`, `VerifyOptions::at(now)` | JWT |
| `hash_password(&str, &[u8], u32)`, `verify_password(&str, &str)`, `needs_rehash(&str, u32)` | Hash kata sandi; salt dipasok pemanggil |
| `hotp`, `totp`, `verify_totp`, `otpauth_uri`, `TotpOptions`, `OtpAlgorithm` | OTP |
| `base32_encode`, `base32_decode` | |
| `Policy::from_value(&Value)`, `Policy::can`, `Policy::effective_permissions` | RBAC |
| `call(fn, args)` | Titik masuk kontrak |
| `crypto::*` | Primitif (SHA-1, SHA-256, HMAC, PBKDF2, base64, hex) |
| `Error { code, message }` | `message_id()` |

## 3. Port lain

Belum ada.

## 4. Kompatibilitas lintas bahasa

Untuk masukan yang sama, TypeScript dan Rust menghasilkan hasil identik pada seluruh vector (381 kasus).
