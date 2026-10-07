# Map LombokAuth v0.1.0

## 1. Posisi dependensi

L0. Posisi cluster dan nomor katalog mengikuti dokumen induk ekosistem v3.6 (tidak di-commit, ADR-024). Tidak memiliki dependensi Lombok wajib.

## 2. Contoh dependen di ekosistem

Bagian ini satu-satunya tempat nama aplikasi atau framework boleh muncul (ADR-019). Ini ilustrasi, bukan kepemilikan; siapa pun dapat memakai LombokAuth.

| Pemakai | Jenis | Status integrasi | Keterangan |
|---|---|---|---|
| LombokClarion v3 | Framework | rencana (F7) | Menggantikan TokenIssuer dan melengkapi Gate di paket auth internal v2 |
| LombokServer | Library L4 | rencana | Middleware autentikasi JWT |
| LombokDocFlow | Aplikasi | rencana | Login, 2FA, dan peran pengguna |

Integrasi opsional ke LombokSecurity (kebijakan kata sandi), LombokSQL (penyimpanan), dan LombokCache (daftar token dicabut) belum diimplementasikan.

## 3. Bergantung pada

Tidak ada.

## 4. Jalur kontrak normatif

`docs/SPEC_LombokAuth_v0.1.0.md` -> `vectors/lombokauth-vectors-v1.json` (sha256 di SPEC) -> runner `rust/tests/vectors.rs` dan `typescript/test/vectors.test.ts`.

## 5. Peta folder

Lihat `structure_repo_LombokAuth_v0.1.0.md`.
