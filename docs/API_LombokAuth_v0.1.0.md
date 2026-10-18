# API LombokAuth v0.1.0

Normative semantics are in `SPEC_LombokAuth_v0.1.0.md`; this document only lists the interfaces that are actually exported.

## 1. TypeScript (package `lombokauth`)

Stability: 0.x, may change in minor releases. `Bytes` is `Uint8Array`; string arguments are read as UTF-8.

| Symbol | Signature | Notes |
|---|---|---|
| `signJwt` | `(claims, secret, options?: { kid? }) => string` | Since 0.1.0 |
| `verifyJwt` | `(token, secret, { now, leeway?, issuer?, audience?, requireExp? }) => { header, claims }` | Throws the first failing code |
| `decodeJwtUnverified` | `(token) => { header, claims }` | Without verification |
| `hashPassword` | `(password, salt: Bytes \| hex, iterations?) => string` | PHC |
| `hashPasswordRandom` | `(password, iterations?) => string` | Salt from `crypto.getRandomValues` |
| `verifyPassword` | `(password, phc) => boolean` | |
| `needsRehash` | `(phc, iterations?) => boolean` | |
| `hotp` | `(secret, counter, { digits?, algorithm? }?) => string` | |
| `totp` | `(secret, timeSeconds, { period?, digits?, algorithm?, t0? }?) => string` | |
| `verifyTotp` | `(secret, code, timeSeconds, { ..., window? }?) => number \| null` | Step offset |
| `otpauthUri` | `(secret, account, issuer, { period?, digits?, algorithm? }?) => string` | |
| `base32Encode`, `base32Decode` | RFC 4648 | |
| `validatePolicy`, `can`, `effectivePermissions` | RBAC | |
| `call` | `(fn: string, args: unknown[]) => unknown` | Contract entry point |
| `DEFAULT_ITERATIONS`, `MIN_ITERATIONS`, `MAX_ITERATIONS`, `MIN_SALT_BYTES`, `MIN_JWT_SECRET_BYTES`, `MAX_INHERITANCE` | constants | |
| `utf8`, `toHex`, `fromHex`, `base64url`, `base64urlDecode`, `sha256`, `hmacSha256`, `pbkdf2Sha256`, `constantTimeEqual` | primitives | From `crypto.ts` |
| `LombokAuthError` | `extends Error`; `code`, `messageId` | Codes: SPEC section 7 |

## 2. Rust (crate `lombokauth`)

Feature: `std` (default). Without `std`, the crate is `no_std + alloc`.

| Symbol | Notes |
|---|---|
| `sign_jwt(&Value, &[u8], Option<&str>)`, `verify_jwt(&str, &[u8], &VerifyOptions)`, `decode_jwt_unverified(&str)`, `VerifyOptions::at(now)` | JWT |
| `hash_password(&str, &[u8], u32)`, `verify_password(&str, &str)`, `needs_rehash(&str, u32)` | Password hashes; the salt is supplied by the caller |
| `hotp`, `totp`, `verify_totp`, `otpauth_uri`, `TotpOptions`, `OtpAlgorithm` | OTP |
| `base32_encode`, `base32_decode` | |
| `Policy::from_value(&Value)`, `Policy::can`, `Policy::effective_permissions` | RBAC |
| `call(fn, args)` | Contract entry point |
| `crypto::*` | Primitives (SHA-1, SHA-256, HMAC, PBKDF2, base64, hex) |
| `Error { code, message }` | `message_id()` |

## 3. Other ports

None yet.

## 4. Cross-language compatibility

For the same input, TypeScript and Rust produce identical results on all vectors (381 cases).
