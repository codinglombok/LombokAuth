import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";
import * as c from "../src/crypto.js";

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

test("crypto: SHA-1, SHA-256, HMAC and base64 agree with node:crypto on random inputs", () => {
  for (let n = 0; n < 300; n++) {
    const b = randomBytes(n);
    const k = randomBytes(n % 150);
    assert.equal(hex(c.sha256(b)), createHash("sha256").update(b).digest("hex"));
    assert.equal(hex(c.sha1(b)), createHash("sha1").update(b).digest("hex"));
    assert.equal(hex(c.hmacSha256(k, b)), createHmac("sha256", k).update(b).digest("hex"));
    assert.equal(hex(c.hmacSha1(k, b)), createHmac("sha1", k).update(b).digest("hex"));
    assert.equal(c.base64url(b), b.toString("base64url"));
    assert.equal(c.base64(b), b.toString("base64"));
    assert.equal(hex(c.base64urlDecode(b.toString("base64url"))!), b.toString("hex"));
    assert.equal(hex(c.base64Decode(b.toString("base64"))!), b.toString("hex"));
    assert.equal(c.toHex(b), b.toString("hex"));
  }
});

test("crypto: PBKDF2-HMAC-SHA256 published vectors and node:crypto", () => {
  const P = c.utf8("password");
  const S = c.utf8("salt");
  assert.equal(hex(c.pbkdf2Sha256(P, S, 1, 32)), "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
  assert.equal(hex(c.pbkdf2Sha256(P, S, 2, 32)), "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
  assert.equal(hex(c.pbkdf2Sha256(P, S, 4096, 32)), "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
  for (const [it, len] of [[1, 1], [3, 33], [5, 64], [7, 70]] as const) {
    const p = randomBytes(11);
    const s = randomBytes(9);
    assert.equal(hex(c.pbkdf2Sha256(p, s, it, len)), pbkdf2Sync(p, s, it, len, "sha256").toString("hex"));
  }
});

test("crypto: strict decoders and UTF-8", () => {
  assert.equal(c.base64urlDecode("-_9"), null, "non-zero trailing bits");
  assert.equal(c.base64urlDecode("A"), null);
  assert.equal(c.base64urlDecode("AB=="), null, "padding not allowed in base64url");
  assert.equal(c.base64Decode("+/8"), null, "padding required");
  assert.equal(c.fromHex("0g"), null);
  assert.equal(c.fromHex("abc"), null);
  const s = "a\u00e9\u{1F600}\ud800x";
  assert.equal(hex(c.utf8(s)), Buffer.from(s, "utf8").toString("hex"));
  assert.equal(c.utf8Decode(c.utf8("caf\u00e9 \u{1F600}")), "caf\u00e9 \u{1F600}");
  for (const bad of [[0xc0, 0x80], [0xed, 0xa0, 0x80], [0xf4, 0x90, 0x80, 0x80], [0xe2, 0x82], [0x80]]) assert.equal(c.utf8Decode(Uint8Array.from(bad)), null, JSON.stringify(bad));
  assert.ok(c.constantTimeEqual(new Uint8Array(0), new Uint8Array(0)));
  assert.ok(!c.constantTimeEqual(c.utf8("ab"), c.utf8("abab")));
});
