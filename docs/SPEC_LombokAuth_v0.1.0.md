# SPEC LombokAuth v0.1.0

This document is the normative cross-language contract. Every language port MUST produce byte-identical output for all specified inputs. Deviations from this specification are bugs.

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as in RFC 2119 and RFC 8174.

| Attribute | Value |
|---|---|
| Contract version | 0.1.0 |
| Review date of reference standards | 2026-10-07 |
| Vectors | `vectors/lombokauth-vectors-v1.json` |
| Vector SHA-256 | `9edfc13e90a369e116c04e6ccff5df53e43132e2df94a6d45cacf772b2513488` |

## 0. Reference standards (U2)

| Reference | Version | Use |
|---|---|---|
| RFC 7519, RFC 7515 | 2015 | JWT and compact JWS serialization |
| RFC 7518 | 2015 | HS256 and the minimum key length (section 3.2) |
| RFC 8725 | 2020 | JWT best practices: algorithm allow-list, rejection of `none` |
| RFC 8018 | 2017 | PBKDF2 |
| PHC string format | 2017 | Password hash format |
| RFC 4226, RFC 6238 | 2005, 2011 | HOTP and TOTP, including the appendix test vectors |
| RFC 4648 | 2006 | base32, base64, base64url |
| Key Uri Format (Google Authenticator) | 2023 | The `otpauth://totp/` URI |
| RFC 3986 | 2005 | Unreserved characters and percent-encoding |
| ECMA-262 | 2024 | JSON serialization of claims (`JSON.stringify`) |
| RFC 2119, RFC 8174 | 1997, 2017 | Normative key words |

## 1. Vectors

The vector file contains `{ format, specVersion, note, groups }`. Each case contains `name`, `fn`, `args` and `expect` (`{ "result": ... }` or `{ "error": code }`). In `args`, an object `{ "hex": "..." }` means bytes; a string means its UTF-8 bytes, except for a salt argument that is a hexadecimal string. Every claimed port MUST run all cases through the entry point `call(fn, args)`. The SHA-256 hash of the file MUST equal the one in the attribute table.

## 2. JWT HS256

The secret MUST be at least 32 bytes (`invalid_secret`).

`signJwt(claims, secret, options?)`: validation order is the secret, the options (`kid`, a non-empty string; `invalid_option`), then the claims (a JSON object with finite numbers; `invalid_claim`). The header is `{"alg":"HS256","typ":"JWT"}` plus `"kid"` if present, in that order. Token = `B64U(JSON(header)) + "." + B64U(JSON(claims)) + "." + B64U(HMAC-SHA256(secret, the first two parts))`, where `JSON` is equivalent to ECMA-262 `JSON.stringify` and `B64U` is base64url without padding.

`verifyJwt(token, secret, options)`: the options MUST be an object with `now` (seconds, a finite number) and optionally `leeway` (a number >= 0, default 0), `issuer`, `audience` (strings), `requireExp` (boolean, default true); other keys or wrong types MUST produce `invalid_option`. Order of checks; the first error is reported:

1. The secret; the options.
2. The token MUST be a string with exactly three segments separated by `.` (`invalid_token`).
3. Header and payload: canonical base64url (no padding, no non-zero trailing bits), valid UTF-8, RFC 8259 JSON, an object, finite numbers, a depth of at most 512 (`invalid_token`). Duplicate keys use the last value.
4. The signature segment is canonical base64url (`invalid_token`).
5. `alg` MUST be exactly `HS256` (`unsupported_alg`); the header may only contain `alg`, `typ`, `kid` (otherwise, including `crit`, `invalid_token`); `typ`, if present, MUST be `JWT`; `kid`, if present, MUST be a string.
6. The signature is compared in constant time (`invalid_signature`).
7. Claim types: `exp`, `nbf`, `iat` numbers; `iss`, `sub` strings; `aud` a string or an array of strings (`invalid_claim`).
8. `exp`: absent and `requireExp` true: `invalid_claim`; present and `now >= exp + leeway`: `token_expired`.
9. `nbf`: `now + leeway < nbf`: `token_not_yet_valid`.
10. `issuer` is given and `iss` is not exactly equal: `invalid_issuer`.
11. `audience` is given and is not equal to `aud` (a string) or is not among `aud` (an array): `invalid_audience`.

The result is `{ header, claims }`. `decodeJwtUnverified(token)` runs steps 2 and 3 only.

## 3. Password hashes

Format: `$pbkdf2-sha256$i=<n>$<salt>$<hash>`, `n` decimal without leading zeros, `salt` and `hash` standard base64 without padding, `hash` = PBKDF2-HMAC-SHA256(UTF-8(password), salt, n, 32).

`hashPassword(password, salt, iterations?)`: the password MUST be a string (`invalid_input`); the salt is bytes or a hexadecimal string of at least 16 bytes (`invalid_salt`); iterations is an integer in 1000..10000000, default 600000 (`invalid_option`).

`verifyPassword(password, phc)`: the PHC MUST match the format above with `n` in 1000..10000000, a salt of at least 16 bytes, a hash of exactly 32 bytes, and canonical base64 (`invalid_hash`); then the password MUST be a string. The comparison is constant-time.

`needsRehash(phc, iterations?)`: iterations is validated first (default 600000), then the PHC; true when `n < iterations`.

## 4. HOTP, TOTP, base32

An OTP secret MUST be at least 10 bytes (`invalid_secret`). Options: `digits` 6..8 (default 6), `algorithm` `SHA1` or `SHA256` (default `SHA1`); other keys `invalid_option`.

`hotp(secret, counter, options?)`: the counter is an integer in 0..2^53-1. The value is the RFC 4226 dynamic truncation of HMAC(secret, the 8-byte big-endian counter) modulo 10^digits, left-padded with zeros.

`totp(secret, time, options?)`: additional options `period` 1..86400 (default 30) and `t0` (default 0); `time` is an integer number of seconds >= `t0`. Step = `floor((time - t0) / period)`; the value is the HOTP of that step. Validation order: secret, digits, algorithm, period, t0, time.

`verifyTotp(secret, code, time, options?)`: additional option `window` 0..10 (default 1). If `code` is not a digit string of length `digits`, the result is null. Otherwise steps `s + d` are checked for `d` from `-window` to `window` in order, skipping negative steps; the result is the first matching `d` (constant-time comparison) or null.

`base32Encode(data)`: RFC 4648 with padding. `base32Decode(text)`: ASCII lowercase is folded; padding is optional but when present the total length MUST be a multiple of 8; the unpadded length modulo 8 MUST NOT be 1, 3 or 6; characters outside the alphabet and non-zero trailing bits MUST produce `invalid_input`. The result in `call` is `{ "hex": ... }`.

`otpauthUri(secret, account, issuer, options?)`: `account` and `issuer` are non-empty strings without `:` (`invalid_input`). Output `otpauth://totp/` + pct(issuer) + `:` + pct(account) + `?secret=` + base32 without padding + `&issuer=` + pct(issuer) + `&algorithm=` + algorithm + `&digits=` + digits + `&period=` + period. `pct` encodes every UTF-8 byte other than `A-Z a-z 0-9 - . _ ~` as `%XX` in uppercase hexadecimal.

## 5. RBAC

Policy: `{ "roles": { name: { "permissions": [...], "inherits": [...] } } }`. A role name MUST match `^[A-Za-z0-9_.-]{1,64}$`. Other keys at any level, a shape that is not an object or array, an invalid name or an invalid inheritance: `invalid_policy`. A `permissions` or `inherits` value of null means an empty array.

A permission is segments separated by `.`, each segment `[A-Za-z0-9_-]+`. A pattern in the policy may use a segment `*` and the prefix `!` (deny). An invalid form: `invalid_permission`. Inheriting from a role that does not exist, a cycle, or an inheritance chain longer than 64 roles: `invalid_policy`. An implementation MUST NOT exhaust its stack on a chain of any length.

Matching a pattern `p` against a permission `x`: segments are compared in order; a `*` in the last position matches one or more remaining segments; a `*` in any other position matches exactly one segment; other segments MUST be exactly equal (case-sensitive); without a trailing `*`, the number of segments MUST be equal.

`can(policy, roles, permission)`: the policy is validated, then `roles` (an array of existing role names; otherwise `invalid_role`), then `permission` (a permission without wildcards; `invalid_permission`). Patterns are collected from the roles and all their inheritance. The result is false if a deny pattern matches; otherwise true if an allow pattern matches; otherwise false.

`effectivePermissions(policy, roles)`: `{ allow, deny }`, each a list of unique patterns sorted by code unit order.

## 6. Security

- An `alg` other than HS256 MUST be rejected, including `none` and case variants; the signature MUST be checked before claims are trusted.
- All secret comparisons (signature, hash, OTP code) MUST be constant-time.
- A PHC with iterations outside 1000..10000000 MUST be rejected to prevent strength downgrade and denial-of-service attacks.
- A deny rule MUST always win over an allow rule, including through inheritance.
- Any input MUST produce a result or an error with a `code` from section 7; a panic or any other exception is a bug.

## 7. Errors

| `code` | Condition | `messageId` |
|---|---|---|
| `invalid_secret` | a JWT secret shorter than 32 bytes or an OTP secret shorter than 10 bytes | `lombokauth.error.invalid_secret` |
| `invalid_token` | invalid token structure, encoding or header | `lombokauth.error.invalid_token` |
| `invalid_signature` | the signature does not match | `lombokauth.error.invalid_signature` |
| `unsupported_alg` | `alg` is not HS256 | `lombokauth.error.unsupported_alg` |
| `token_expired` | `exp` has passed | `lombokauth.error.token_expired` |
| `token_not_yet_valid` | `nbf` has not been reached | `lombokauth.error.token_not_yet_valid` |
| `invalid_issuer` | `iss` does not match | `lombokauth.error.invalid_issuer` |
| `invalid_audience` | `aud` does not match | `lombokauth.error.invalid_audience` |
| `invalid_claim` | a claim of the wrong type, an invalid claim when signing, or a required `exp` is missing | `lombokauth.error.invalid_claim` |
| `invalid_salt` | the salt is shorter than 16 bytes or not hexadecimal | `lombokauth.error.invalid_salt` |
| `invalid_hash` | invalid PHC string | `lombokauth.error.invalid_hash` |
| `invalid_option` | invalid option; unknown function | `lombokauth.error.invalid_option` |
| `invalid_input` | an argument of the wrong type or encoding | `lombokauth.error.invalid_input` |
| `invalid_policy` | invalid policy | `lombokauth.error.invalid_policy` |
| `invalid_role` | unknown role | `lombokauth.error.invalid_role` |
| `invalid_permission` | invalid permission name or pattern | `lombokauth.error.invalid_permission` |

## 8. Non-goals (0.1.0)

Asymmetric JWT algorithms, JWE, JWKS, refresh tokens and revocation, Argon2id and bcrypt, WebAuthn, session storage, and ABAC (attributes).

## 9. Contract change history

| Version | Change |
|---|---|
| 0.1.0 | Initial contract |
