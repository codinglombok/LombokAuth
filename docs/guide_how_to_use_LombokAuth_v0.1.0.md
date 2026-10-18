# Guide How To Use LombokAuth v0.1.0

## Installation

Not published yet. After the release: `npm install lombokauth` or `cargo add lombokauth`. Until then, build from the repository (see `CONTRIBUTING.md`).

## Basic concepts

1. **Time** is always supplied as seconds (`now`); the library never reads the clock.
2. A JWT **secret** is at least 32 random bytes; an OTP secret is at least 10 bytes (20 recommended).
3. Verification **errors** carry a code that can be logged (`token_expired`, `invalid_signature`); do not show that code to end users.

## Example

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

### Enabling TOTP

```ts
import { otpauthUri, verifyTotp } from "lombokauth";
const uri = otpauthUri(secretBytes, "ana@example.com", "Example");   // show it as a QR code
const offset = verifyTotp(secretBytes, input, Math.floor(Date.now() / 1000));
if (offset === null) reject();
```

For the secret `12345678901234567890`, the URI is `otpauth://totp/Example:ana%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA1&digits=6&period=30`. Store the last step that was used (the current step plus the offset) and reject codes with the same or an older step to prevent replay.

### Upgrading an old hash at login

```ts
import { verifyPassword, needsRehash, hashPasswordRandom } from "lombokauth";
if (verifyPassword(input, user.hash) && needsRehash(user.hash)) user.hash = hashPasswordRandom(input);
```

### RBAC as data

```ts
import { can, effectivePermissions } from "lombokauth";
const policy = { roles: { viewer: { permissions: ["posts.read"] }, editor: { permissions: ["posts.*", "!posts.delete"], inherits: ["viewer"] } } };
can(policy, ["editor"], "posts.edit");           // true
effectivePermissions(policy, ["editor"]);
// {"allow":["posts.*","posts.read"],"deny":["posts.delete"]}
```

## Common pitfalls

- `decodeJwtUnverified` checks nothing; do not use it for access decisions.
- `exp` is required by default; a token without `exp` is rejected unless `requireExp: false`.
- `now` is in seconds, not milliseconds.
- `posts.*` does not match `posts` itself; add both when you need that.
- A `!deny` rule from any role (including an inherited role) always wins.
- 600000 PBKDF2 iterations take real time in pure TypeScript; measure on the target device and adjust.

## See also

README, SPEC_, API_.
