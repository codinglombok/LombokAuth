# Lang LombokAuth v0.1.0

## 1. Tingkat i18n

Tingkat **E** (pesan error dan dokumentasi saja). Library tidak menghasilkan teks untuk pengguna akhir selain pesan galat.

## 2. Katalog ID pesan (normatif)

Format `lombokauth.<jenis>.<kode>`. Berkas katalog: `locales/<bcp47>/lombokauth.json`, satu berkas untuk semua port.

| ID | Teks sumber (en) | Kode galat |
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

Galat membawa `code` (kontrak, sama di semua port) dan `messageId`. Pesan `message` di objek galat berbahasa Inggris dan tidak bersifat normatif.

## 3. Cakupan saat ini

Core-20: 2 dari 20 (`en`, `id`). Paket Nusantara: 0 dari 6. Bahasa lain belum ada. Katalog bahasa tambahan harus ditinjau penutur asli sebelum diterima.

## 4. Cara menambah bahasa

1. Salin `locales/en/lombokauth.json` ke `locales/<bcp47>/lombokauth.json`.
2. Terjemahkan nilai; kunci tidak diubah.
3. Minta tinjauan penutur asli, lalu ajukan PR.

## 5. Ketergantungan LombokLocale

Tidak ada pada 0.1.0. Konsumen yang memakai LombokLocale dapat me-resolve `messageId` terhadap katalog di atas.
