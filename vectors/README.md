# Vectors

`lombokauth-vectors-v1.json` adalah kontrak uji lintas bahasa untuk LombokAuth.

- SHA-256: `9edfc13e90a369e116c04e6ccff5df53e43132e2df94a6d45cacf772b2513488` (harus sama dengan `docs/SPEC_LombokAuth_v0.1.0.md`).
- Dibangkitkan oleh `scripts/gen-vectors.mjs`. Grup `golden`: ekspektasi ditulis tangan, disalin dari RFC 4226 lampiran D, RFC 6238 lampiran B, dan RFC 4648 bagian 10, atau dibangun dengan `node:crypto` (token JWT dan hash PBKDF2), lalu dicocokkan dengan port TypeScript saat pembangkitan. Grup `generated-regression`: masukan acak berbenih, ekspektasi dari port TypeScript dan dikonfirmasi port Rust.
- Setiap kasus memanggil fungsi `fn` dengan `args`; `expect` berbentuk `{ "result": ... }` atau `{ "error": code }`.
- Setiap port yang diklaim MUST menjalankan seluruh kasus.
- Jumlah: 381 kasus (211 golden berekspektasi tulis tangan, dari RFC, atau dibangun dengan node:crypto, 170 regresi hasil pembangkit).
