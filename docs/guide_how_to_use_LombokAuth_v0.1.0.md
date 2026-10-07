# Guide How To Use LombokAuth v0.1.0

## Instalasi

Belum terbit. Setelah rilis: `npm install lombokauth` atau `cargo add lombokauth`. Sebelum itu, bangun dari repo (lihat `CONTRIBUTING.md`).

## Konsep dasar

1. **Waktu** selalu dipasok sebagai detik (`now`); library tidak membaca jam.
2. **Secret** JWT paling sedikit 32 byte acak; secret OTP paling sedikit 10 byte (disarankan 20).
3. **Galat** verifikasi membawa kode yang dapat dicatat (`token_expired`, `invalid_signature`); jangan tampilkan kode itu ke pengguna akhir.

## Contoh

```ts
import { signJwt, verifyJwt, LombokAuthError } from "lombokauth";

const now = Math.floor(Date.now() / 1000);
const access = signJwt({ sub: user.id, iss: "https://id.example.com", aud: "api", exp: now + 900 }, secret);
try {
  const { claims } = verifyJwt(access, secret, { now, issuer: "https://id.example.com", audience: "api", leeway: 30 });
} catch (e) {
  if (e instanceof LombokAuthError) reply(401);
}
```

## Recipes

### Mengaktifkan TOTP

```ts
import { otpauthUri, verifyTotp } from "lombokauth";
const uri = otpauthUri(secretBytes, "ana@example.com", "Example");   // tampilkan sebagai kode QR
const offset = verifyTotp(secretBytes, input, Math.floor(Date.now() / 1000));
if (offset === null) reject();
```

Untuk secret `12345678901234567890`, URI-nya adalah `otpauth://totp/Example:ana%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA1&digits=6&period=30`. Simpan langkah terakhir yang dipakai (langkah saat ini ditambah offset) dan tolak kode dengan langkah yang sama atau lebih lama untuk mencegah replay.

### Memperbarui hash lama saat login

```ts
import { verifyPassword, needsRehash, hashPasswordRandom } from "lombokauth";
if (verifyPassword(input, user.hash) && needsRehash(user.hash)) user.hash = hashPasswordRandom(input);
```

### RBAC sebagai data

```ts
import { can, effectivePermissions } from "lombokauth";
const policy = { roles: { viewer: { permissions: ["posts.read"] }, editor: { permissions: ["posts.*", "!posts.delete"], inherits: ["viewer"] } } };
can(policy, ["editor"], "posts.edit");           // true
effectivePermissions(policy, ["editor"]);
// {"allow":["posts.*","posts.read"],"deny":["posts.delete"]}
```

## Common pitfalls

- `decodeJwtUnverified` tidak memeriksa apa pun; jangan dipakai untuk keputusan akses.
- `exp` wajib secara bawaan; token tanpa `exp` ditolak kecuali `requireExp: false`.
- `now` dalam detik, bukan milidetik.
- `posts.*` tidak cocok dengan `posts` sendiri; tambahkan keduanya bila perlu.
- Aturan `!tolak` dari peran mana pun (termasuk peran warisan) selalu menang.
- 600000 iterasi PBKDF2 memakan waktu nyata di TypeScript murni; ukur di perangkat target dan sesuaikan.

## Lihat juga

README, SPEC_, API_.
