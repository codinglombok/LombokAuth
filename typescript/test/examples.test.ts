import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { can, effectivePermissions, hashPassword, needsRehash, otpauthUri, signJwt, totp, verifyJwt, verifyPassword } from "../src/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const read = (p: string): string => readFileSync(join(root, p), "utf8");

test("README quick-start comments match the library", () => {
  const secret = "a-string-secret-at-least-256-bits-long";
  const now = 1700000000;
  const token = signJwt({ sub: "user-1", iss: "https://id.example.com", exp: now + 900 }, secret);
  assert.equal(verifyJwt(token, secret, { now, issuer: "https://id.example.com" }).claims["sub"], "user-1");
  assert.equal(totp("12345678901234567890", 59), "287082");
  assert.equal(can({ roles: { editor: { permissions: ["posts.*", "!posts.delete"] } } }, ["editor"], "posts.delete"), false);
  const r = read("README.md");
  assert.ok(r.includes('totp("12345678901234567890", 59);                                 // "287082"'));
});

test("guide recipes behave as documented", () => {
  const g = read("docs/guide_how_to_use_LombokAuth_v0.1.0.md");
  const uri = otpauthUri("12345678901234567890", "ana@example.com", "Example");
  assert.ok(g.includes(uri), uri);
  const old = hashPassword("pw", "000102030405060708090a0b0c0d0e0f", 1000);
  assert.ok(verifyPassword("pw", old) && needsRehash(old, 600000));
  const policy = { roles: { viewer: { permissions: ["posts.read"] }, editor: { permissions: ["posts.*", "!posts.delete"], inherits: ["viewer"] } } };
  const eff = JSON.stringify(effectivePermissions(policy, ["editor"]));
  assert.equal(eff, '{"allow":["posts.*","posts.read"],"deny":["posts.delete"]}');
  assert.ok(g.includes(eff));
});
