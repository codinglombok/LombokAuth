# Changelog LombokAuth (summary)

The newest entry comes first. Details are in `CHANGELOG.md`.

## 0.1.0 - 2026-10-07

### Added
- JWT HS256, PBKDF2 PHC password hashes, HOTP/TOTP, RBAC.
- Rust `no_std + alloc` port and TypeScript port.
- 381 vectors; runners in both ports; fuzzing and mutation testing.

### Security
- HS256 only; `none` and other algorithms are rejected; the signature is checked before claims.
- Constant-time secret comparison; PBKDF2 iteration limit of 1000..10000000.
- Deny rules always win; the inheritance chain is bounded without risk of stack overflow.
