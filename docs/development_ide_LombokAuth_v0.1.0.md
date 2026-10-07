# Development IDE LombokAuth v0.1.0

## 1. Roadmap

| Versi | Isi |
|---|---|
| 0.1.1 | Tutup syarat rilis: CI dijalankan, `doctor docs/privacy/style`, coverage diukur, target `cargo-fuzz` |
| 0.2.0 | EdDSA (Ed25519) untuk JWT; Argon2id; daftar pencabutan berbasis `jti`; port Python, Go, PHP |
| 0.3.0 | JWKS dan rotasi kunci (`kid`); ABAC sederhana; integrasi opsional LombokSQL dan LombokCache |

## 2. Deferred scope

Lihat SPEC bagian Non-goals dan README (Batasan).

## 3. Prinsip desain kontributor

- Kontrak dulu, test dulu; semua port lulus vector yang sama.
- Tidak ada dependensi runtime; dev-dependency dicatat.
- Fungsi inti murni: jam, keacakan, dan I/O dipasok pemanggil.
- Bawaan yang aman: `exp` wajib, iterasi tinggi, hanya algoritma yang diizinkan.
- Setiap aturan penolakan memiliki vector golden.

## 4. Cara berkontribusi

Lihat `CONTRIBUTING.md`.

## 5. Pertanyaan terbuka

- Apakah `iat` di masa depan (melebihi leeway) sebaiknya ditolak?
- Apakah izin sebaiknya tidak peka huruf besar-kecil?
