import { test } from "node:test";
import assert from "node:assert/strict";
import { LombokAuthError, can, hashPasswordRandom, needsRehash, signJwt, validatePolicy, verifyJwt, verifyPassword, verifyTotp, totp } from "../src/index.js";

const S = "a-string-secret-at-least-256-bits-long";

test("hashPasswordRandom salts every hash differently", () => {
  const a = hashPasswordRandom("pw", 1000);
  const b = hashPasswordRandom("pw", 1000);
  assert.notEqual(a, b);
  assert.ok(verifyPassword("pw", a) && verifyPassword("pw", b));
  assert.ok(needsRehash(a));
});

test("sign then verify round-trips claims", () => {
  const claims = { sub: "u", exp: 2000, roles: ["a"], n: { x: 1 } };
  assert.deepEqual(verifyJwt(signJwt(claims, S), S, { now: 1000 }).claims, claims);
});

test("errors carry a messageId", () => {
  try {
    verifyJwt("a.b.c", "short", { now: 0 });
    assert.fail("expected throw");
  } catch (e) {
    assert.ok(e instanceof LombokAuthError);
    assert.equal(e.messageId, "lombokauth.error.invalid_secret");
  }
});

test("a very long inheritance chain is rejected without exhausting the stack", () => {
  const roles: Record<string, unknown> = {};
  for (let i = 0; i < 200000; i++) roles[`r${i}`] = i === 0 ? {} : { inherits: [`r${i - 1}`] };
  assert.throws(() => validatePolicy({ roles }), (e: unknown) => e instanceof LombokAuthError && e.code === "invalid_policy");
});

test("TOTP verify accepts exactly the codes inside the window", () => {
  const k = "12345678901234567890";
  for (let t = 30; t < 3000; t += 7) {
    assert.equal(verifyTotp(k, totp(k, t), t), 0);
    assert.equal(verifyTotp(k, totp(k, t + 30), t), 1);
    assert.equal(verifyTotp(k, totp(k, t - 30), t), -1);
  }
});

// Pseudo-fuzz: mutated tokens never verify and never throw anything but LombokAuthError.
test("fuzz: mutated JWTs are always rejected", () => {
  let seed = 5;
  const rnd = (): number => ((seed = (seed * 1103515245 + 12345) >>> 0) / 4294967296);
  const good = signJwt({ sub: "u", exp: 2000 }, S);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.=+/ ";
  for (let i = 0; i < 5000; i++) {
    const chars = good.split("");
    const n = 1 + Math.floor(rnd() * 3);
    for (let k = 0; k < n; k++) chars[Math.floor(rnd() * chars.length)] = alphabet[Math.floor(rnd() * alphabet.length)]!;
    const t = chars.join("");
    if (t === good) continue;
    try {
      verifyJwt(t, S, { now: 1000 });
      assert.fail(`mutated token verified: ${t}`);
    } catch (e) {
      assert.ok(e instanceof LombokAuthError, String(e));
    }
  }
});

test("can: deny always wins regardless of role order", () => {
  const p = { roles: { a: { permissions: ["x.*"] }, b: { permissions: ["!x.y"] } } };
  assert.equal(can(p, ["a", "b"], "x.y"), false);
  assert.equal(can(p, ["b", "a"], "x.y"), false);
  assert.equal(can(p, ["a", "b"], "x.z"), true);
});
