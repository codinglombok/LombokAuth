# Development IDE LombokAuth v0.1.0

## 1. Roadmap

| Version | Content |
|---|---|
| 0.1.1 | Close the release conditions: CI run, `doctor docs/privacy/style`, coverage measured, a `cargo-fuzz` target |
| 0.2.0 | EdDSA (Ed25519) for JWT; Argon2id; a revocation list based on `jti`; Python, Go and PHP ports |
| 0.3.0 | JWKS and key rotation (`kid`); simple ABAC; optional LombokSQL and LombokCache integration |

## 2. Deferred scope

See the Non-goals section of the SPEC and the README (Known limitations).

## 3. Design principles for contributors

- Contract first, tests first; all ports pass the same vectors.
- No runtime dependencies; dev dependencies are recorded.
- Core functions are pure: the clock, randomness and I/O are supplied by the caller.
- Secure defaults: `exp` is required, high iteration counts, only allowed algorithms.
- Every rejection rule has a golden vector.
- English is the default language for all documents, code comments and messages.

## 4. How to contribute

See `CONTRIBUTING.md`.

## 5. Open questions

- Should an `iat` in the future (beyond the leeway) be rejected?
- Should permissions be case-insensitive?
