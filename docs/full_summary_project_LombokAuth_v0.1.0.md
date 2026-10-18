# Full Summary LombokAuth v0.1.0

## What it is

A dependency-free authentication core: JWT HS256 with strict verification, PBKDF2 password hashes in PHC format, HOTP/TOTP, and RBAC with wildcards, inheritance and deny rules.

## Why it exists

Authentication vulnerabilities generally come from the rules around the cryptography: accepting `alg: none`, not checking `exp`, comparisons that are not constant-time, or hash iteration counts that are too low. The libraries of each language have different defaults. A shared contract fixes secure defaults that are identical in every port.

## Main features

See the README (Features section). All features are covered by vectors.

## Current status

Complete code for Rust and TypeScript; passes 381 vector cases; not yet published to any registry; does not yet meet the release score rule (see `TECH_DEBT.md`).

## Example users

See the README (usage scenarios).

## Known Limitations

- JWT is HS256 only; no asymmetric algorithms, JWE or JWKS.
- PBKDF2 only; Argon2id is not available yet.
- The cryptography has not been audited by a third party.
- TOTP replay prevention and token revocation are the responsibility of the application.
- The Rust port has no source of randomness.
- Only two ports (Rust, TypeScript); fuzzing is pseudo-fuzzing, not `cargo-fuzz`; no third-party audit; coverage not measured yet.

## More information

`SPEC_`, `API_`, `development_ide_`.

## Gap vs comparators (U6)

The comparison is qualitative and based on general knowledge of each category of library; it has not been verified feature by feature on 2026-10-07.

| Comparator (category) | What the comparator has that LombokAuth does not | What LombokAuth offers |
|---|---|---|
| JWT and auth libraries (jose, jsonwebtoken, PyJWT, otplib, Casbin) | Asymmetric algorithms, JWKS, storage adapters, richer policy models | A cross-language contract with RFC vectors; secure defaults; a `no_std + alloc` core; no dependencies |
| Identity providers (Keycloak, Auth0) | Full OAuth2/OIDC, UI, federation | An embeddable component without a server |
