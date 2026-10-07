# SPEC LombokAuth v0.1.0

This document is the normative cross-language contract. Every language port MUST produce byte-identical output for all specified inputs. Deviations from this specification are bugs.

Key words MUST, MUST NOT, SHOULD and MAY are interpreted as in RFC 2119 and RFC 8174.

| Atribut | Nilai |
|---|---|
| Versi kontrak | 0.1.0 |
| Tanggal tinjauan standar acuan | 2026-10-07 |
| Vector | `vectors/lombokauth-vectors-v1.json` |
| SHA-256 vector | `9edfc13e90a369e116c04e6ccff5df53e43132e2df94a6d45cacf772b2513488` |

## 0. Standar acuan (U2)

| Acuan | Versi | Pemakaian |
|---|---|---|
| RFC 7519, RFC 7515 | 2015 | JWT dan serialisasi compact JWS |
| RFC 7518 | 2015 | HS256 dan panjang kunci minimum (bagian 3.2) |
| RFC 8725 | 2020 | Praktik terbaik JWT: allow-list algoritma, penolakan `none` |
| RFC 8018 | 2017 | PBKDF2 |
| PHC string format | 2017 | Format hash kata sandi |
| RFC 4226, RFC 6238 | 2005, 2011 | HOTP dan TOTP, termasuk vector uji lampiran |
| RFC 4648 | 2006 | base32, base64, base64url |
| Key Uri Format (Google Authenticator) | 2023 | URI `otpauth://totp/` |
| RFC 3986 | 2005 | Karakter unreserved dan percent-encoding |
| ECMA-262 | 2024 | Serialisasi JSON klaim (`JSON.stringify`) |
| RFC 2119, RFC 8174 | 1997, 2017 | Kata kunci normatif |

## 1. Vector

Berkas vector memuat `{ format, specVersion, note, groups }`. Setiap kasus memuat `name`, `fn`, `args`, `expect` (`{ "result": ... }` atau `{ "error": code }`). Dalam `args`, objek `{ "hex": "..." }` berarti byte; string berarti byte UTF-8-nya, kecuali argumen salt yang berupa string heksadesimal. Setiap port yang diklaim MUST menjalankan seluruh kasus lewat titik masuk `call(fn, args)`. Hash SHA-256 berkas MUST sama dengan tabel atribut.

## 2. JWT HS256

Secret MUST paling sedikit 32 byte (`invalid_secret`).

`signJwt(claims, secret, options?)`: urutan validasi secret, opsi (`kid`, string tidak kosong; `invalid_option`), klaim (objek JSON dengan angka berhingga; `invalid_claim`). Header adalah `{"alg":"HS256","typ":"JWT"}` ditambah `"kid"` bila ada, dalam urutan itu. Token = `B64U(JSON(header)) + "." + B64U(JSON(claims)) + "." + B64U(HMAC-SHA256(secret, dua bagian pertama))`, dengan `JSON` setara `JSON.stringify` ECMA-262 dan `B64U` base64url tanpa padding.

`verifyJwt(token, secret, options)`: opsi MUST objek dengan `now` (detik, angka berhingga) dan opsional `leeway` (angka >= 0, bawaan 0), `issuer`, `audience` (string), `requireExp` (boolean, bawaan true); kunci lain atau tipe salah MUST `invalid_option`. Urutan pemeriksaan, galat pertama dilaporkan:

1. secret; opsi.
2. Token MUST string dengan tepat tiga segmen dipisah `.` (`invalid_token`).
3. Header dan payload: base64url kanonik (tanpa padding, tanpa bit sisa bukan nol), UTF-8 sah, JSON RFC 8259, objek, angka berhingga, kedalaman paling besar 512 (`invalid_token`). Kunci duplikat memakai nilai terakhir.
4. Segmen tanda tangan base64url kanonik (`invalid_token`).
5. `alg` MUST tepat `HS256` (`unsupported_alg`); header hanya boleh memuat `alg`, `typ`, `kid` (selain itu, termasuk `crit`, `invalid_token`); `typ` bila ada MUST `JWT`; `kid` bila ada MUST string.
6. Tanda tangan dibandingkan waktu-konstan (`invalid_signature`).
7. Tipe klaim: `exp`, `nbf`, `iat` angka; `iss`, `sub` string; `aud` string atau array string (`invalid_claim`).
8. `exp`: tidak ada dan `requireExp` true: `invalid_claim`; ada dan `now >= exp + leeway`: `token_expired`.
9. `nbf`: `now + leeway < nbf`: `token_not_yet_valid`.
10. `issuer` diberikan dan `iss` tidak sama persis: `invalid_issuer`.
11. `audience` diberikan dan tidak sama dengan `aud` (string) atau tidak termasuk `aud` (array): `invalid_audience`.

Hasil `{ header, claims }`. `decodeJwtUnverified(token)` menjalankan langkah 2 dan 3 saja.

## 3. Hash kata sandi

Format: `$pbkdf2-sha256$i=<n>$<salt>$<hash>`, `n` desimal tanpa nol di depan, `salt` dan `hash` base64 standar tanpa padding, `hash` = PBKDF2-HMAC-SHA256(UTF-8(password), salt, n, 32).

`hashPassword(password, salt, iterations?)`: password MUST string (`invalid_input`); salt byte atau string heksadesimal, paling sedikit 16 byte (`invalid_salt`); iterations bilangan bulat 1000..10000000, bawaan 600000 (`invalid_option`).

`verifyPassword(password, phc)`: PHC MUST cocok format di atas dengan `n` 1000..10000000, salt paling sedikit 16 byte, hash tepat 32 byte, dan base64 kanonik (`invalid_hash`); lalu password MUST string. Perbandingan waktu-konstan.

`needsRehash(phc, iterations?)`: iterations divalidasi lebih dulu (bawaan 600000), lalu PHC; true bila `n < iterations`.

## 4. HOTP, TOTP, base32

Secret OTP MUST paling sedikit 10 byte (`invalid_secret`). Opsi: `digits` 6..8 (bawaan 6), `algorithm` `SHA1` atau `SHA256` (bawaan `SHA1`); kunci lain `invalid_option`.

`hotp(secret, counter, options?)`: counter bilangan bulat 0..2^53-1. Nilai = truncation dinamis RFC 4226 atas HMAC(secret, counter 8 byte big-endian) modulo 10^digits, diisi nol di depan.

`totp(secret, time, options?)`: opsi tambahan `period` 1..86400 (bawaan 30) dan `t0` (bawaan 0); `time` bilangan bulat detik >= `t0`. Langkah = `floor((time - t0) / period)`; nilai = HOTP langkah itu. Urutan validasi: secret, digits, algorithm, period, t0, time.

`verifyTotp(secret, code, time, options?)`: opsi tambahan `window` 0..10 (bawaan 1). Bila `code` bukan string digit sepanjang `digits`, hasil null. Selain itu diperiksa langkah `s + d` untuk `d` dari `-window` sampai `window` berurutan, melewati langkah negatif; hasil adalah `d` pertama yang cocok (perbandingan waktu-konstan) atau null.

`base32Encode(data)`: RFC 4648 dengan padding. `base32Decode(text)`: huruf kecil ASCII dilipat; padding opsional tetapi bila ada panjang total MUST kelipatan 8; panjang tanpa padding modulo 8 MUST bukan 1, 3, atau 6; karakter di luar alfabet dan bit sisa bukan nol MUST `invalid_input`. Hasil di `call` adalah `{ "hex": ... }`.

`otpauthUri(secret, account, issuer, options?)`: `account` dan `issuer` string tidak kosong tanpa `:` (`invalid_input`). Keluaran `otpauth://totp/` + pct(issuer) + `:` + pct(account) + `?secret=` + base32 tanpa padding + `&issuer=` + pct(issuer) + `&algorithm=` + algoritma + `&digits=` + digits + `&period=` + period. `pct` meng-encode setiap byte UTF-8 selain `A-Z a-z 0-9 - . _ ~` sebagai `%XX` heksadesimal huruf besar.

## 5. RBAC

Kebijakan: `{ "roles": { nama: { "permissions": [...], "inherits": [...] } } }`. Nama peran MUST cocok `^[A-Za-z0-9_.-]{1,64}$`. Kunci lain di tingkat mana pun, bentuk bukan objek atau array, nama atau pewarisan tidak sah: `invalid_policy`. `permissions` atau `inherits` bernilai null berarti array kosong.

Izin adalah segmen dipisah `.`, setiap segmen `[A-Za-z0-9_-]+`. Pola di kebijakan boleh memakai segmen `*` dan awalan `!` (tolak). Bentuk tidak sah: `invalid_permission`. Pewarisan ke peran yang tidak ada, siklus, atau rantai pewarisan lebih panjang dari 64 peran: `invalid_policy`. Implementasi MUST tidak kehabisan stack pada rantai sepanjang apa pun.

Pencocokan pola `p` terhadap izin `x`: segmen dibandingkan berurutan; `*` di posisi terakhir cocok dengan satu atau lebih segmen sisa; `*` di posisi lain cocok dengan tepat satu segmen; segmen lain MUST sama persis (peka huruf); tanpa `*` terakhir, jumlah segmen MUST sama.

`can(policy, roles, permission)`: kebijakan divalidasi, lalu `roles` (array nama peran yang ada; selain itu `invalid_role`), lalu `permission` (izin tanpa wildcard; `invalid_permission`). Pola dikumpulkan dari peran dan seluruh pewarisannya. Hasil false bila ada pola tolak yang cocok; selain itu true bila ada pola izin yang cocok; selain itu false.

`effectivePermissions(policy, roles)`: `{ allow, deny }`, masing-masing pola unik terurut menurut urutan code unit.

## 6. Keamanan

- `alg` selain HS256 MUST ditolak, termasuk `none` dan varian huruf; tanda tangan MUST diperiksa sebelum klaim dipercaya.
- Semua perbandingan rahasia (tanda tangan, hash, kode OTP) MUST waktu-konstan.
- PHC dengan iterasi di luar 1000..10000000 MUST ditolak untuk mencegah penurunan kekuatan dan serangan penolakan layanan.
- Aturan tolak MUST selalu menang atas aturan izin, termasuk lewat pewarisan.
- Masukan apa pun MUST menghasilkan hasil atau galat dengan `code` pada bagian 7; panic atau pengecualian lain adalah bug.

## 7. Galat

| `code` | Kondisi | `messageId` |
|---|---|---|
| `invalid_secret` | secret JWT kurang dari 32 byte atau secret OTP kurang dari 10 byte | `lombokauth.error.invalid_secret` |
| `invalid_token` | struktur, encoding, atau header token tidak sah | `lombokauth.error.invalid_token` |
| `invalid_signature` | tanda tangan tidak cocok | `lombokauth.error.invalid_signature` |
| `unsupported_alg` | `alg` bukan HS256 | `lombokauth.error.unsupported_alg` |
| `token_expired` | `exp` terlewati | `lombokauth.error.token_expired` |
| `token_not_yet_valid` | `nbf` belum tercapai | `lombokauth.error.token_not_yet_valid` |
| `invalid_issuer` | `iss` tidak cocok | `lombokauth.error.invalid_issuer` |
| `invalid_audience` | `aud` tidak cocok | `lombokauth.error.invalid_audience` |
| `invalid_claim` | klaim bertipe salah, klaim tidak sah saat menandatangani, atau `exp` wajib tidak ada | `lombokauth.error.invalid_claim` |
| `invalid_salt` | salt kurang dari 16 byte atau bukan heksadesimal | `lombokauth.error.invalid_salt` |
| `invalid_hash` | string PHC tidak sah | `lombokauth.error.invalid_hash` |
| `invalid_option` | opsi tidak sah; fungsi tak dikenal | `lombokauth.error.invalid_option` |
| `invalid_input` | argumen bertipe atau ber-encoding salah | `lombokauth.error.invalid_input` |
| `invalid_policy` | kebijakan tidak sah | `lombokauth.error.invalid_policy` |
| `invalid_role` | peran tidak dikenal | `lombokauth.error.invalid_role` |
| `invalid_permission` | nama izin atau pola tidak sah | `lombokauth.error.invalid_permission` |

## 8. Non-goals (0.1.0)

Algoritma JWT asimetris, JWE, JWKS, refresh token dan pencabutan, Argon2id dan bcrypt, WebAuthn, penyimpanan sesi, dan ABAC (atribut).

## 9. Riwayat perubahan kontrak

| Versi | Perubahan |
|---|---|
| 0.1.0 | Kontrak awal |
