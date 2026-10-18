# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/); the newest entry comes first. Versions follow [SemVer](https://semver.org/).

## [0.1.0] - 2026-10-07

### Added
- JWT HS256: `signJwt`, `verifyJwt` (algorithm allow-list, rejection of `crit`, canonical base64url, required `exp`, `nbf`, `iss`, `aud`, `leeway`), `decodeJwtUnverified`.
- PBKDF2-HMAC-SHA256 password hashes in PHC format: `hashPassword`, `verifyPassword`, `needsRehash`.
- HOTP and TOTP (SHA1, SHA256), `verifyTotp` with a step offset, `otpauthUri`, RFC 4648 base32.
- RBAC: permission patterns with `*`, deny rules, inheritance with cycle detection and a chain limit of 64.
- Rust port (`no_std + alloc`, no dependencies) and TypeScript port (no runtime dependencies).
- Shared vectors of 381 cases (211 golden cases with hand-written, RFC or `node:crypto` expectations, 170 generated regression cases), executed by the Rust and TypeScript runners.
- Pseudo-fuzzing and a mutation-testing script (25 mutants).

### Security
- HS256 only; `none` and other algorithms are rejected; the signature is checked before claims.
- Constant-time secret comparison; PBKDF2 iteration limit of 1000..10000000.
- Deny rules always win; the inheritance chain is bounded without risk of stack overflow.
