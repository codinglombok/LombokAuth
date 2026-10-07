# Kebijakan Keamanan

## Versi yang didukung

| Versi | Dukungan |
|---|---|
| 0.1.x | Perbaikan keamanan |

## Melaporkan kerentanan

Gunakan **GitHub Private Vulnerability Reporting** pada repo ini (tab Security, "Report a vulnerability"). Jangan membuka issue publik untuk kerentanan.

- Respons awal: paling lama 48 jam.
- Perbaikan untuk temuan kritis: target 7 hari.
- Pengungkapan dikoordinasikan dengan pelapor.

## Cakupan

Dalam cakupan: seluruh fungsi yang diekspor, khususnya penerimaan JWT yang tidak sah (algoritma `none`, tanda tangan salah, klaim kedaluwarsa), kebocoran waktu pada verifikasi, kesalahan RBAC yang memberi izin berlebih, dan panic atau waktu eksekusi tak terbatas.

Di luar cakupan: penyimpanan pengguna, sesi, dan sumber keacakan yang dipasok aplikasi; algoritma JWT selain HS256.

## Model ancaman ringkas

Lihat bagian Keamanan pada `docs/SPEC_LombokAuth_v0.1.0.md`.
