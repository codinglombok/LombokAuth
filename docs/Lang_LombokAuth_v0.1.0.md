# Lang LombokAuth v0.1.0

## 1. i18n level

Level **E** (error messages and documentation only). The library produces no end-user text other than error messages. The source language of all messages and documentation is English.

## 2. Message ID catalog (normative)

Format `lombokauth.<kind>.<code>`. Catalog files: `locales/<bcp47>/lombokauth.json`, one file for all ports.

| ID | Source text (en) | Error code |
|---|---|---|
| `lombokauth.error.invalid_secret` | The secret is missing or too short. | `invalid_secret` |
| `lombokauth.error.invalid_token` | The token is malformed. | `invalid_token` |
| `lombokauth.error.invalid_signature` | The token signature is not valid. | `invalid_signature` |
| `lombokauth.error.unsupported_alg` | The token algorithm is not accepted. | `unsupported_alg` |
| `lombokauth.error.token_expired` | The token has expired. | `token_expired` |
| `lombokauth.error.token_not_yet_valid` | The token is not valid yet. | `token_not_yet_valid` |
| `lombokauth.error.invalid_issuer` | The token issuer is not accepted. | `invalid_issuer` |
| `lombokauth.error.invalid_audience` | The token audience is not accepted. | `invalid_audience` |
| `lombokauth.error.invalid_claim` | A token claim has an invalid type or is missing. | `invalid_claim` |
| `lombokauth.error.invalid_salt` | The salt must be at least 16 bytes. | `invalid_salt` |
| `lombokauth.error.invalid_hash` | The stored password hash is malformed or unsupported. | `invalid_hash` |
| `lombokauth.error.invalid_option` | An option is invalid. | `invalid_option` |
| `lombokauth.error.invalid_input` | An argument has the wrong type or encoding. | `invalid_input` |
| `lombokauth.error.invalid_policy` | The access policy is invalid. | `invalid_policy` |
| `lombokauth.error.invalid_role` | A role is unknown. | `invalid_role` |
| `lombokauth.error.invalid_permission` | A permission name is invalid. | `invalid_permission` |

An error carries `code` (contract, the same in all ports) and `messageId`. The `message` field of the error object is in English and is not normative.

## 3. Current coverage

Core-20: 2 of 20 (`en`, `id`). Nusantara pack: 0 of 6. No other languages yet. Catalogs for additional languages must be reviewed by a native speaker before they are accepted.

## 4. How to add a language

1. Copy `locales/en/lombokauth.json` to `locales/<bcp47>/lombokauth.json`.
2. Translate the values; keys are not changed.
3. Ask a native speaker to review, then open a pull request.

## 5. Dependency on LombokLocale

None in 0.1.0. A consumer that uses LombokLocale can resolve `messageId` against the catalogs above.
