# Tech Debt LombokAuth

Format: ID, temuan, prioritas, perbaikan, status. Prioritas P1 memblokir rilis minor; P0 memblokir tag 0.1.0.

| ID | Temuan | Prioritas | Perbaikan | Status |
|---|---|---|---|---|
| TD-01 | `ci.yml` belum pernah dijalankan di GitHub Actions; action belum di-pin SHA | P0 | Jalankan di repo, pin SHA, aktifkan Dependabot | OPEN |
| TD-02 | `lombok doctor docs/privacy/style` belum ada (TD-P0-08 ekosistem); pemeriksaan otomatis terbatas pada `docs.test.ts` | P0 | Jalankan setelah `codinglombok/.github` ada | OPEN |
| TD-03 | Coverage belum diukur; target 90% | P1 | Tambah job coverage Rust dan TS | OPEN |
| TD-04 | Fuzz bukan `cargo-fuzz`; fuzz Rust belum ada | P1 | Target `cargo-fuzz` untuk `call` | OPEN |
| TD-05 | Hanya Rust dan TypeScript; port Python, Go, PHP BELUM | P1 | Rencana 0.2.0 | OPEN |
| TD-06 | Salinan `LICENSE-*` di `rust/` | P3 | Otomatiskan salinan saat rilis | OPEN |
| TD-07 | Kasus regresi (170) berekspektasi dari TS dan dikonfirmasi port Rust; hanya 211 golden yang independen | P3 | Tinjau manual sebagian kasus regresi | OPEN |
| TD-08 | Modul kripto belum diaudit pihak ketiga | P1 | Audit sebelum 1.0 | OPEN |
| TD-09 | PBKDF2 600000 iterasi di TypeScript murni belum diukur kinerjanya | P2 | Benchmark; pertimbangkan WebCrypto opsional | OPEN |

Sudah ditutup di 0.1.0: `no_std` dibuktikan dengan build `thumbv7em-none-eabi` dan clippy/rustfmt dijalankan dengan `-D warnings` (lokal; CI menjalankan yang sama).
