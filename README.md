# LombokAuth

[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue)](LICENSE-APACHE)

A dependency-free authentication core: **JWT HS256** with strict claim verification, **PBKDF2-SHA256 password hashes** in PHC format, **HOTP/TOTP** for authenticator apps, and **RBAC** with wildcards, role inheritance and deny rules. Pure functions: salt, secret and time are supplied by the caller. The output is identical in every port.

Part of the [Lombok Ecosystem](https://github.com/codinglombok).

## Why this library?

The most common authentication mistakes are not in the cryptography but in the rules around it: accepting `alg: none`, forgetting to check `exp`, comparing signatures with `==`, or storing password hashes with too few iterations. Every language has libraries with different defaults. LombokAuth specifies those rules normatively, rejects doubtful forms explicitly, and proves them with shared vectors, including the vectors of RFC 4226, RFC 6238 and RFC 4648.

Usage scenarios:

- **Web services and APIs**: short-lived HS256 access tokens with checks on `iss`, `aud`, `exp` and `nbf`.
- **Registration and login**: PBKDF2 hashes in PHC format and detection of when a hash needs to be upgraded.
- **Two-factor authentication**: TOTP compatible with authenticator apps, including the `otpauth://` URI for QR codes.
- **Authorization**: RBAC policy as JSON data that can be inspected and shared between services written in different languages.
- **Serverless, edge and embedded devices**: a `no_std + alloc` Rust core without dependencies.

Other dependents in the Lombok Ecosystem are listed in `docs/map_LombokAuth_v0.1.0.md`.

## Features

Every feature below is covered by vectors in `vectors/` and by TypeScript tests.

- `signJwt`, `verifyJwt`, `decodeJwtUnverified`: HS256 only; `none` and other algorithms are rejected; `crit` is rejected; canonical base64url; `exp` is required by default; `leeway`, `issuer`, `audience`.
- `hashPassword`, `verifyPassword`, `needsRehash`: PBKDF2-HMAC-SHA256, 600000 iterations by default, a salt of at least 16 bytes, format `$pbkdf2-sha256$i=...$salt$hash`.
- `hotp`, `totp`, `verifyTotp`, `otpauthUri`, `base32Encode`, `base32Decode`: SHA1 and SHA256, 6 to 8 digits, a verification window with a step offset for replay detection.
- `can`, `effectivePermissions`, `validatePolicy`: dotted permissions with `*`, `!deny` rules that always win, inheritance with cycle detection and a chain limit of 64.
- `hashPasswordRandom` (TypeScript) uses `crypto.getRandomValues`.

## Installation

Not published to any registry yet. After the first release:

```bash
npm install lombokauth      # TypeScript / JavaScript
cargo add lombokauth        # Rust
```

## Quick Start

### TypeScript

```ts
import { signJwt, verifyJwt, hashPasswordRandom, verifyPassword, totp, can } from "lombokauth";

const secret = process.env.JWT_SECRET!;                          // at least 32 bytes
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

## Port status

| Port | Status | Evidence |
|---|---|---|
| Rust (`no_std + alloc`) | YES, passes the vectors | `rust/tests/vectors.rs` runs every vector; a test of a 200000-role inheritance chain; `thumbv7em-none-eabi` build |
| TypeScript | YES, passes the vectors | `typescript/test/vectors.test.ts` runs every vector; the cryptography is compared with `node:crypto`; fuzzing of mutated tokens |
| Python, Go, PHP, Java, Kotlin, C#, C/C++, Swift, Perl | NOT YET | No code; planned once the contract is stable (see `docs/development_ide_LombokAuth_v0.1.0.md`) |

Vectors: 381 cases (211 golden cases with hand-written expectations, taken from RFCs, or built with `node:crypto`; 170 generated regression cases).

## Standards implemented

RFC 7519 (JWT), RFC 7515 (compact JWS), RFC 7518 section 3.2 (HS256, key length), RFC 8725 (JWT best practices: algorithm allow-list), RFC 8018 (PBKDF2), the PHC string format, RFC 4226 (HOTP), RFC 6238 (TOTP), RFC 4648 (base32, base64url), the Key Uri Format (`otpauth://`). See `docs/SPEC_LombokAuth_v0.1.0.md`.

## Known limitations

- JWT is HS256 only; there is no RS256, ES256, EdDSA, JWE or JWKS.
- PBKDF2 was chosen because it can be implemented without dependencies in every port; Argon2id is stronger against GPU attacks and is planned as an option.
- The cryptography implementation has not been audited by a third party.
- TOTP does not store the steps that have been used; replay prevention uses the offset returned by `verifyTotp` together with storage owned by the application.
- The Rust port has no source of randomness; the salt is supplied by the caller.
- Only Rust and TypeScript have code. Fuzzing is pseudo-fuzzing, not `cargo-fuzz`.

## Lombok Ecosystem

LombokAuth has no required dependency on other Lombok libraries (L0). Other libraries may use it optionally; the dependents are listed in `docs/map_LombokAuth_v0.1.0.md`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

`Apache-2.0 OR MIT`. See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).
