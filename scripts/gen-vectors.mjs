// Generates vectors/lombokauth-vectors-v1.json.
// Group "golden": expectations are WRITTEN BY HAND or copied from the cited standard (RFC 4226
// appendix D, RFC 6238 appendix B, RFC 4648 section 10). JWT tokens and PBKDF2 hashes in golden
// cases are built with node:crypto (an independent implementation), not with the library. Every
// golden case is checked against the TypeScript port at generation time; a disagreement aborts.
// Group "generated-regression": seeded random inputs whose expectations come from the TypeScript
// port and are confirmed by the independent Rust port.
import { createHash, createHmac, pbkdf2Sync } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { isDeepStrictEqual } from "node:util";
import * as lib from "../typescript/dist/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function run(fn, args) {
  try {
    return { result: JSON.parse(JSON.stringify(lib.call(fn, args))) };
  } catch (err) {
    if (!(err instanceof lib.LombokAuthError)) throw err;
    return { error: err.code };
  }
}
const golden = [];
function g(name, fn, args, expect) {
  const got = run(fn, args);
  if (!isDeepStrictEqual(got, expect)) {
    throw new Error(`golden mismatch in "${name}"\n  expected ${JSON.stringify(expect)}\n  got      ${JSON.stringify(got)}`);
  }
  golden.push({ name, fn, args, expect });
}
const ok = (result) => ({ result });
const err = (error) => ({ error });
const hex = (h) => ({ hex: h });
const asciiHex = (s) => Buffer.from(s, "ascii").toString("hex");

// ---------------------------------------------------------------- HOTP (RFC 4226 appendix D)
const K20 = "12345678901234567890";
["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"].forEach((code, c) =>
  g(`hotp rfc4226 counter ${c}`, "hotp", [K20, c], ok(code)),
);
g("hotp secret as bytes", "hotp", [hex(asciiHex(K20)), 0], ok("755224"));
g("hotp 8 digits", "hotp", [K20, 0, { digits: 8 }], ok("84755224"));
g("hotp large counter", "hotp", [K20, 4294967296], ok(lib.hotp(K20, 4294967296)));
g("hotp short secret", "hotp", ["123456789", 0], err("invalid_secret"));
g("hotp digits 5", "hotp", [K20, 0, { digits: 5 }], err("invalid_option"));
g("hotp digits 9", "hotp", [K20, 0, { digits: 9 }], err("invalid_option"));
g("hotp negative counter", "hotp", [K20, -1], err("invalid_option"));
g("hotp fractional counter", "hotp", [K20, 1.5], err("invalid_option"));
g("hotp unknown algorithm", "hotp", [K20, 0, { algorithm: "MD5" }], err("invalid_option"));
g("hotp unknown option", "hotp", [K20, 0, { digit: 6 }], err("invalid_option"));

// ---------------------------------------------------------------- TOTP (RFC 6238 appendix B)
const K32 = "12345678901234567890123456789012";
const T6238 = [
  [59, "94287082", "46119246"],
  [1111111109, "07081804", "68084774"],
  [1111111111, "14050471", "67062674"],
  [1234567890, "89005924", "91819424"],
  [2000000000, "69279037", "90698825"],
  [20000000000, "65353130", "77737706"],
];
for (const [t, sha1, sha256] of T6238) {
  g(`totp rfc6238 SHA1 t=${t}`, "totp", [K20, t, { digits: 8 }], ok(sha1));
  g(`totp rfc6238 SHA256 t=${t}`, "totp", [K32, t, { digits: 8, algorithm: "SHA256" }], ok(sha256));
}
g("totp default 6 digits", "totp", [K20, 59], ok("287082"));
g("totp period 60", "totp", [K20, 119, { period: 60 }], ok("287082"));
g("totp t0", "totp", [K20, 1059, { t0: 1000 }], ok("287082"));
g("totp before t0", "totp", [K20, 10, { t0: 1000 }], err("invalid_option"));
g("totp negative time", "totp", [K20, -1], err("invalid_option"));
g("totp fractional time", "totp", [K20, 1.5], err("invalid_option"));
g("totp period zero", "totp", [K20, 0, { period: 0 }], err("invalid_option"));
g("verifyTotp current step", "verifyTotp", [K20, "287082", 59], ok(0));
g("verifyTotp previous step", "verifyTotp", [K20, "287082", 60], ok(-1));
g("verifyTotp next step", "verifyTotp", [K20, "359152", 59], ok(1));
g("verifyTotp outside window", "verifyTotp", [K20, "969429", 59], ok(null));
g("verifyTotp wider window", "verifyTotp", [K20, "969429", 59, { window: 2 }], ok(2));
g("verifyTotp window 0", "verifyTotp", [K20, "287082", 60, { window: 0 }], ok(null));
g("verifyTotp step 0 no negative steps", "verifyTotp", [K20, "755224", 0], ok(0));
// At t=0 the step before is -1; it must be skipped, never wrapped to counter 2^64-1 (HOTP value 094451, computed with node:crypto).
g("verifyTotp negative step not wrapped", "verifyTotp", [K20, "094451", 0], ok(null));
g("verifyTotp wrong length", "verifyTotp", [K20, "28708", 59], ok(null));
g("verifyTotp non-digits", "verifyTotp", [K20, "28708a", 59], ok(null));
g("verifyTotp non-string code", "verifyTotp", [K20, 287082, 59], ok(null));
g("verifyTotp window too large", "verifyTotp", [K20, "287082", 59, { window: 11 }], err("invalid_option"));

// ---------------------------------------------------------------- base32 (RFC 4648 section 10)
const B32 = [["", ""], ["f", "MY======"], ["fo", "MZXQ===="], ["foo", "MZXW6==="], ["foob", "MZXW6YQ="], ["fooba", "MZXW6YTB"], ["foobar", "MZXW6YTBOI======"]];
for (const [plain, enc] of B32) {
  g(`base32 encode ${JSON.stringify(plain)}`, "base32Encode", [plain], ok(enc));
  g(`base32 decode ${JSON.stringify(enc)}`, "base32Decode", [enc], ok(hex(asciiHex(plain))));
}
g("base32 decode lowercase", "base32Decode", ["mzxw6ytboi"], ok(hex(asciiHex("foobar"))));
g("base32 decode without padding", "base32Decode", ["MZXW6YQ"], ok(hex(asciiHex("foob"))));
g("base32 decode bad length", "base32Decode", ["MZXW6Y"], err("invalid_input"));
g("base32 decode length 1", "base32Decode", ["A"], err("invalid_input"));
g("base32 decode length 3", "base32Decode", ["AAA"], err("invalid_input"));
g("base32 decode length 6 with zero bits", "base32Decode", ["MZXW6A"], err("invalid_input"));
g("base32 decode bad char", "base32Decode", ["MZ1W"], err("invalid_input"));
g("base32 decode partial padding", "base32Decode", ["MY=="], err("invalid_input"));
g("base32 decode non-zero trailing bits", "base32Decode", ["MZ======"], err("invalid_input"));
g("base32 decode non-ASCII not folded", "base32Decode", ["M\u00df"], err("invalid_input"));

// ---------------------------------------------------------------- otpauth URI
g("otpauth basic", "otpauthUri", [K20, "ana@example.com", "Example"], ok("otpauth://totp/Example:ana%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA1&digits=6&period=30"));
g("otpauth encoding", "otpauthUri", [K20, "ana wijaya", "Lombok App (Dev)", { digits: 8, period: 60, algorithm: "SHA256" }], ok("otpauth://totp/Lombok%20App%20%28Dev%29:ana%20wijaya?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Lombok%20App%20%28Dev%29&algorithm=SHA256&digits=8&period=60"));
g("otpauth utf-8", "otpauthUri", [K20, "caf\u00e9", "X"], ok("otpauth://totp/X:caf%C3%A9?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=X&algorithm=SHA1&digits=6&period=30"));
g("otpauth colon in account", "otpauthUri", [K20, "a:b", "X"], err("invalid_input"));
g("otpauth empty issuer", "otpauthUri", [K20, "a", ""], err("invalid_input"));

// ---------------------------------------------------------------- JWT
const S = "a-string-secret-at-least-256-bits-long";
const b64u = (s) => Buffer.from(s, "utf8").toString("base64url");
const mk = (headerJson, payloadJson, secret = S) => {
  const input = `${b64u(headerJson)}.${b64u(payloadJson)}`;
  return `${input}.${createHmac("sha256", secret).update(input).digest("base64url")}`;
};
const HS = '{"alg":"HS256","typ":"JWT"}';
const now = 1700000000;
const V = { now };
const tok = (payload) => mk(HS, payload);
const T1 = tok('{"sub":"user-1","iat":1699999000,"exp":1700000600}');
g("jwt sign matches independent HMAC", "signJwt", [{ sub: "user-1", iat: 1699999000, exp: 1700000600 }, S], ok(T1));
g("jwt sign with kid", "signJwt", [{ a: 1 }, S, { kid: "k1" }], ok(mk('{"alg":"HS256","typ":"JWT","kid":"k1"}', '{"a":1}')));
g("jwt sign key order is ECMAScript order", "signJwt", [{ b: 1, 2: "x", a: [1.5, null] }, S], ok(tok('{"2":"x","b":1,"a":[1.5,null]}')));
g("jwt sign unicode claim", "signJwt", [{ n: "caf\u00e9" }, S], ok(tok('{"n":"caf\u00e9"}')));
g("jwt sign short secret", "signJwt", [{ a: 1 }, "short"], err("invalid_secret"));
g("jwt sign 31-byte secret", "signJwt", [{ a: 1 }, "x".repeat(31)], err("invalid_secret"));
g("jwt sign 32-byte secret", "signJwt", [{ a: 1 }, "x".repeat(32)], ok(mk(HS, '{"a":1}', "x".repeat(32))));
g("jwt sign claims not object", "signJwt", [[1], S], err("invalid_claim"));
g("jwt sign empty kid", "signJwt", [{ a: 1 }, S, { kid: "" }], err("invalid_option"));
g("jwt verify ok", "verifyJwt", [T1, S, V], ok({ header: { alg: "HS256", typ: "JWT" }, claims: { sub: "user-1", iat: 1699999000, exp: 1700000600 } }));
g("jwt verify secret bytes", "verifyJwt", [T1, hex(Buffer.from(S).toString("hex")), V], ok({ header: { alg: "HS256", typ: "JWT" }, claims: { sub: "user-1", iat: 1699999000, exp: 1700000600 } }));
g("jwt wrong secret", "verifyJwt", [T1, S + "x", V], err("invalid_signature"));
g("jwt tampered payload", "verifyJwt", [`${T1.split(".")[0]}.${b64u('{"sub":"admin","exp":1700000600}')}.${T1.split(".")[2]}`, S, V], err("invalid_signature"));
g("jwt alg none", "verifyJwt", [`${b64u('{"alg":"none","typ":"JWT"}')}.${b64u('{"exp":1700000600}')}.`, S, V], err("unsupported_alg"));
g("jwt alg none with signature", "verifyJwt", [mk('{"alg":"none"}', '{"exp":1700000600}'), S, V], err("unsupported_alg"));
g("jwt alg HS512 rejected", "verifyJwt", [mk('{"alg":"HS512"}', '{"exp":1700000600}'), S, V], err("unsupported_alg"));
g("jwt alg lowercase rejected", "verifyJwt", [mk('{"alg":"hs256"}', '{"exp":1700000600}'), S, V], err("unsupported_alg"));
g("jwt alg missing", "verifyJwt", [mk('{"typ":"JWT"}', '{"exp":1700000600}'), S, V], err("unsupported_alg"));
g("jwt crit rejected", "verifyJwt", [mk('{"alg":"HS256","crit":["exp"]}', '{"exp":1700000600}'), S, V], err("invalid_token"));
g("jwt typ other rejected", "verifyJwt", [mk('{"alg":"HS256","typ":"at+jwt"}', '{"exp":1700000600}'), S, V], err("invalid_token"));
g("jwt typ absent accepted", "verifyJwt", [mk('{"alg":"HS256"}', '{"exp":1700000600}'), S, V], ok({ header: { alg: "HS256" }, claims: { exp: 1700000600 } }));
g("jwt expired at exact exp", "verifyJwt", [tok('{"exp":1700000000}'), S, V], err("token_expired"));
g("jwt one second before exp", "verifyJwt", [tok('{"exp":1700000001}'), S, V], ok({ header: { alg: "HS256", typ: "JWT" }, claims: { exp: 1700000001 } }));
g("jwt leeway", "verifyJwt", [tok('{"exp":1699999990}'), S, { now, leeway: 30 }], ok({ header: { alg: "HS256", typ: "JWT" }, claims: { exp: 1699999990 } }));
g("jwt fractional exp", "verifyJwt", [tok('{"exp":1700000000.5}'), S, V], ok({ header: { alg: "HS256", typ: "JWT" }, claims: { exp: 1700000000.5 } }));
g("jwt nbf future", "verifyJwt", [tok('{"exp":1800000000,"nbf":1700000001}'), S, V], err("token_not_yet_valid"));
g("jwt nbf now", "verifyJwt", [tok('{"exp":1800000000,"nbf":1700000000}'), S, V], ok({ header: { alg: "HS256", typ: "JWT" }, claims: { exp: 1800000000, nbf: 1700000000 } }));
g("jwt nbf leeway", "verifyJwt", [tok('{"exp":1800000000,"nbf":1700000010}'), S, { now, leeway: 10 }], ok({ header: { alg: "HS256", typ: "JWT" }, claims: { exp: 1800000000, nbf: 1700000010 } }));
g("jwt exp required by default", "verifyJwt", [tok('{"sub":"x"}'), S, V], err("invalid_claim"));
g("jwt exp optional", "verifyJwt", [tok('{"sub":"x"}'), S, { now, requireExp: false }], ok({ header: { alg: "HS256", typ: "JWT" }, claims: { sub: "x" } }));
g("jwt exp string", "verifyJwt", [tok('{"exp":"1800000000"}'), S, V], err("invalid_claim"));
g("jwt iat string", "verifyJwt", [tok('{"exp":1800000000,"iat":"x"}'), S, V], err("invalid_claim"));
g("jwt iss number", "verifyJwt", [tok('{"exp":1800000000,"iss":1}'), S, V], err("invalid_claim"));
g("jwt sub number", "verifyJwt", [tok('{"exp":1800000000,"sub":1}'), S, V], err("invalid_claim"));
g("jwt aud mixed array", "verifyJwt", [tok('{"exp":1800000000,"aud":["a",1]}'), S, V], err("invalid_claim"));
g("jwt issuer ok", "verifyJwt", [tok('{"exp":1800000000,"iss":"https://id.example.com"}'), S, { now, issuer: "https://id.example.com" }], ok({ header: { alg: "HS256", typ: "JWT" }, claims: { exp: 1800000000, iss: "https://id.example.com" } }));
g("jwt issuer mismatch", "verifyJwt", [tok('{"exp":1800000000,"iss":"https://evil.example.net"}'), S, { now, issuer: "https://id.example.com" }], err("invalid_issuer"));
g("jwt issuer missing", "verifyJwt", [tok('{"exp":1800000000}'), S, { now, issuer: "https://id.example.com" }], err("invalid_issuer"));
g("jwt audience string", "verifyJwt", [tok('{"exp":1800000000,"aud":"api"}'), S, { now, audience: "api" }], ok({ header: { alg: "HS256", typ: "JWT" }, claims: { exp: 1800000000, aud: "api" } }));
g("jwt audience array", "verifyJwt", [tok('{"exp":1800000000,"aud":["web","api"]}'), S, { now, audience: "api" }], ok({ header: { alg: "HS256", typ: "JWT" }, claims: { exp: 1800000000, aud: ["web", "api"] } }));
g("jwt audience mismatch", "verifyJwt", [tok('{"exp":1800000000,"aud":["web"]}'), S, { now, audience: "api" }], err("invalid_audience"));
g("jwt audience missing", "verifyJwt", [tok('{"exp":1800000000}'), S, { now, audience: "api" }], err("invalid_audience"));
g("jwt expired checked before issuer", "verifyJwt", [tok('{"exp":1,"iss":"x"}'), S, { now, issuer: "y" }], err("token_expired"));
g("jwt signature checked before claims", "verifyJwt", [mk(HS, '{"exp":1}', S + "!"), S, V], err("invalid_signature"));
g("jwt two segments", "verifyJwt", [T1.split(".").slice(0, 2).join("."), S, V], err("invalid_token"));
g("jwt four segments", "verifyJwt", [T1 + ".x", S, V], err("invalid_token"));
g("jwt padded base64", "verifyJwt", [`${b64u(HS)}=.${T1.split(".")[1]}.${T1.split(".")[2]}`, S, V], err("invalid_token"));
g("jwt standard base64 chars", "verifyJwt", [`${T1.split(".")[0]}.${T1.split(".")[1]}.${T1.split(".")[2].replace(/-/g, "+").replace(/_/g, "/")}${/[-_]/.test(T1.split(".")[2]) ? "" : "+"}`, S, V], err("invalid_token"));
g("jwt payload not JSON", "verifyJwt", [mk(HS, "not json"), S, V], err("invalid_token"));
g("jwt payload array", "verifyJwt", [mk(HS, "[1]"), S, V], err("invalid_token"));
g("jwt payload invalid utf-8", "verifyJwt", [`${b64u(HS)}.${Buffer.from([0x7b, 0xff, 0x7d]).toString("base64url")}.AA`, S, V], err("invalid_token"));
g("jwt payload lone surrogate", "verifyJwt", [mk(HS, '{"exp":1800000000,"x":"\\ud800"}'), S, V], err("invalid_token"));
g("jwt payload non-finite number", "verifyJwt", [mk(HS, '{"exp":1e400}'), S, V], err("invalid_token"));
g("jwt duplicate claim last wins", "verifyJwt", [mk(HS, '{"exp":1,"exp":1800000000}'), S, V], ok({ header: { alg: "HS256", typ: "JWT" }, claims: { exp: 1800000000 } }));
g("jwt empty signature", "verifyJwt", [`${T1.split(".")[0]}.${T1.split(".")[1]}.`, S, V], err("invalid_signature"));
g("jwt token not string", "verifyJwt", [null, S, V], err("invalid_token"));
g("jwt verify short secret", "verifyJwt", [T1, "short", V], err("invalid_secret"));
g("jwt verify missing now", "verifyJwt", [T1, S, {}], err("invalid_option"));
g("jwt verify options null", "verifyJwt", [T1, S, null], err("invalid_option"));
g("jwt verify negative leeway", "verifyJwt", [T1, S, { now, leeway: -1 }], err("invalid_option"));
g("jwt verify unknown option", "verifyJwt", [T1, S, { now, aud: "x" }], err("invalid_option"));
g("jwt decode unverified", "decodeJwtUnverified", [mk('{"alg":"none"}', '{"sub":"x"}')], ok({ header: { alg: "none" }, claims: { sub: "x" } }));
g("jwt decode unverified malformed", "decodeJwtUnverified", ["a.b"], err("invalid_token"));

// ---------------------------------------------------------------- password hashing
const SALT = "000102030405060708090a0b0c0d0e0f";
const phc = (pw, saltHex, n) => {
  const salt = Buffer.from(saltHex, "hex");
  const h = pbkdf2Sync(Buffer.from(pw, "utf8"), salt, n, 32, "sha256");
  return `$pbkdf2-sha256$i=${n}$${salt.toString("base64").replace(/=+$/, "")}$${h.toString("base64").replace(/=+$/, "")}`;
};
const H1 = phc("correct horse", SALT, 1000);
g("hash matches independent PBKDF2", "hashPassword", ["correct horse", SALT, 1000], ok(H1));
g("hash salt as bytes", "hashPassword", ["correct horse", hex(SALT), 1000], ok(H1));
g("hash unicode password", "hashPassword", ["kata sandi caf\u00e9", SALT, 1000], ok(phc("kata sandi caf\u00e9", SALT, 1000)));
g("hash empty password", "hashPassword", ["", SALT, 1000], ok(phc("", SALT, 1000)));
g("hash 24-byte salt", "hashPassword", ["x", SALT + "1011121314151617", 1001], ok(phc("x", SALT + "1011121314151617", 1001)));
g("hash short salt", "hashPassword", ["x", "0001", 1000], err("invalid_salt"));
g("hash 15-byte salt", "hashPassword", ["x", "00".repeat(15), 1000], err("invalid_salt"));
g("hash bad hex salt", "hashPassword", ["x", "zz".repeat(16), 1000], err("invalid_salt"));
g("hash too few iterations", "hashPassword", ["x", SALT, 999], err("invalid_option"));
g("hash too many iterations", "hashPassword", ["x", SALT, 10000001], err("invalid_option"));
g("hash password not string", "hashPassword", [1, SALT, 1000], err("invalid_input"));
g("verify ok", "verifyPassword", ["correct horse", H1], ok(true));
g("verify wrong", "verifyPassword", ["correct horsE", H1], ok(false));
g("verify empty vs non-empty", "verifyPassword", ["", H1], ok(false));
g("verify other format rejected", "verifyPassword", ["x", "$argon2id$v=19$m=65536,t=3,p=4$abc$def"], err("invalid_hash"));
g("verify malformed", "verifyPassword", ["x", "$pbkdf2-sha256$i=1000$abc"], err("invalid_hash"));
g("verify iterations below minimum", "verifyPassword", ["x", H1.replace("i=1000", "i=999")], err("invalid_hash"));
g("verify iterations leading zero", "verifyPassword", ["x", H1.replace("i=1000", "i=01000")], err("invalid_hash"));
g("verify iterations too large", "verifyPassword", ["x", H1.replace("i=1000", "i=99999999")], err("invalid_hash"));
g("verify padded base64 rejected", "verifyPassword", ["x", H1 + "="], err("invalid_hash"));
g("verify short hash rejected", "verifyPassword", ["x", H1.slice(0, -4)], err("invalid_hash"));
g("verify 15-byte salt rejected", "verifyPassword", ["x", phc("x", "00".repeat(15), 1000)], err("invalid_hash"));
const B64A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
// 32 bytes = 43 characters; the last character carries 2 padding bits, so flipping its lowest bit is non-canonical.
g("verify non-canonical base64 rejected", "verifyPassword", ["x", H1.slice(0, -1) + B64A[B64A.indexOf(H1.slice(-1)) ^ 1]], err("invalid_hash"));
g("verify not string", "verifyPassword", ["x", null], err("invalid_hash"));
g("needsRehash lower", "needsRehash", [H1, 2000], ok(true));
g("needsRehash equal", "needsRehash", [H1, 1000], ok(false));
g("needsRehash default", "needsRehash", [H1], ok(true));
g("needsRehash malformed", "needsRehash", ["x", 1000], err("invalid_hash"));

// ---------------------------------------------------------------- RBAC
const POL = {
  roles: {
    viewer: { permissions: ["posts.read", "comments.read"] },
    editor: { permissions: ["posts.*", "!posts.delete", "comments.*.own"], inherits: ["viewer"] },
    admin: { permissions: ["*"], inherits: ["editor"] },
    auditor: { permissions: ["*.read", "!billing.read"] },
  },
};
const CAN = (name, roles, perm, r) => g(`can ${name}`, "can", [POL, roles, perm], ok(r));
CAN("viewer reads posts", ["viewer"], "posts.read", true);
CAN("viewer cannot edit", ["viewer"], "posts.edit", false);
CAN("editor edits", ["editor"], "posts.edit", true);
CAN("editor trailing star matches deeper", ["editor"], "posts.edit.title", true);
CAN("trailing star needs one segment", ["editor"], "posts", false);
CAN("editor inherits viewer", ["editor"], "comments.read", true);
CAN("middle star matches one segment", ["editor"], "comments.edit.own", true);
CAN("middle star not two segments", ["editor"], "comments.edit.x.own", false);
CAN("deny wins over allow", ["editor"], "posts.delete", false);
CAN("deny is inherited even by admin", ["admin"], "posts.delete", false);
CAN("admin star", ["admin"], "billing.refund", true);
CAN("leading star", ["auditor"], "users.read", true);
CAN("leading star one segment", ["auditor"], "users.profile.read", false);
CAN("deny in other role wins", ["admin", "auditor"], "billing.read", false);
CAN("no roles", [], "posts.read", false);
CAN("case-sensitive", ["viewer"], "Posts.read", false);
g("can unknown role", "can", [POL, ["owner"], "posts.read"], err("invalid_role"));
g("can roles not array", "can", [POL, "viewer", "posts.read"], err("invalid_role"));
g("can wildcard in checked permission", "can", [POL, ["viewer"], "posts.*"], err("invalid_permission"));
g("can empty segment", "can", [POL, ["viewer"], "posts..read"], err("invalid_permission"));
g("can permission not string", "can", [POL, ["viewer"], 1], err("invalid_permission"));
g("policy cycle", "validatePolicy", [{ roles: { a: { inherits: ["b"] }, b: { inherits: ["a"] } } }], err("invalid_policy"));
g("policy self cycle", "validatePolicy", [{ roles: { a: { inherits: ["a"] } } }], err("invalid_policy"));
g("policy unknown inherited", "validatePolicy", [{ roles: { a: { inherits: ["x"] } } }], err("invalid_policy"));
g("policy unknown role key", "validatePolicy", [{ roles: { a: { perms: [] } } }], err("invalid_policy"));
g("policy unknown top key", "validatePolicy", [{ roles: {}, version: 1 }], err("invalid_policy"));
g("policy bad role name", "validatePolicy", [{ roles: { "a b": {} } }], err("invalid_policy"));
g("policy bad permission", "validatePolicy", [{ roles: { a: { permissions: ["a b"] } } }], err("invalid_permission"));
g("policy bare deny", "validatePolicy", [{ roles: { a: { permissions: ["!"] } } }], err("invalid_permission"));
g("policy partial wildcard segment", "validatePolicy", [{ roles: { a: { permissions: ["posts.ed*"] } } }], err("invalid_permission"));
g("policy permissions not array", "validatePolicy", [{ roles: { a: { permissions: "x" } } }], err("invalid_policy"));
g("policy not object", "validatePolicy", [[]], err("invalid_policy"));
g("policy null lists are empty", "validatePolicy", [{ roles: { a: { permissions: null, inherits: null } } }], ok(true));
g("policy diamond ok", "validatePolicy", [{ roles: { a: {}, b: { inherits: ["a"] }, c: { inherits: ["a"] }, d: { inherits: ["b", "c"] } } }], ok(true));
let chain = {};
for (let i = 0; i < 65; i++) chain[`r${i}`] = i === 0 ? {} : { inherits: [`r${i - 1}`] };
g("policy inheritance chain of 65 rejected", "validatePolicy", [{ roles: chain }], err("invalid_policy"));
const chain64 = {};
for (let i = 0; i < 64; i++) chain64[`r${i}`] = i === 0 ? {} : { inherits: [`r${i - 1}`] };
g("policy inheritance chain of 64 accepted", "validatePolicy", [{ roles: chain64 }], ok(true));
const rev = {};
for (let i = 64; i >= 0; i--) rev[`r${i}`] = i === 0 ? {} : { inherits: [`r${i - 1}`] };
g("policy chain limit independent of key order", "validatePolicy", [{ roles: rev }], err("invalid_policy"));
g("effective permissions", "effectivePermissions", [POL, ["editor"]], ok({ allow: ["comments.*.own", "comments.read", "posts.*", "posts.read"], deny: ["posts.delete"] }));
g("effective permissions union", "effectivePermissions", [POL, ["viewer", "auditor"]], ok({ allow: ["*.read", "comments.read", "posts.read"], deny: ["billing.read"] }));

g("unknown function", "nope", [], err("invalid_option"));

// ---------------------------------------------------------------- generated regression
let seed = 0xa07e1234;
const rnd = () => ((seed = (seed * 1103515245 + 12345) >>> 0) / 4294967296);
const pick = (a) => a[Math.floor(rnd() * a.length)];
const randHex = (n) => Array.from({ length: n }, () => Math.floor(rnd() * 256).toString(16).padStart(2, "0")).join("");
const generated = [];
const push = (name, fn, args) => generated.push({ name: `generated ${String(generated.length + 1).padStart(3, "0")} ${name}`, fn, args, expect: run(fn, args) });
for (let i = 0; i < 40; i++) push("hotp", "hotp", [hex(randHex(10 + Math.floor(rnd() * 40))), Math.floor(rnd() * 1e12), { digits: pick([6, 7, 8]), algorithm: pick(["SHA1", "SHA256"]) }]);
for (let i = 0; i < 30; i++) push("totp", "totp", [hex(randHex(20)), Math.floor(rnd() * 4e9), { period: pick([15, 30, 60]), digits: pick([6, 8]) }]);
for (let i = 0; i < 20; i++) push("base32", "base32Encode", [hex(randHex(Math.floor(rnd() * 30)))]);
for (let i = 0; i < 40; i++) {
  const claims = { sub: `u${i}`, exp: now + Math.floor((rnd() - 0.3) * 1000) };
  if (rnd() < 0.5) claims.nbf = now + Math.floor((rnd() - 0.7) * 100);
  if (rnd() < 0.5) claims.aud = pick(["api", ["api", "web"], "web"]);
  if (rnd() < 0.5) claims.iss = pick(["https://id.example.com", "other"]);
  let t = lib.signJwt(claims, S);
  if (rnd() < 0.2) t = t.slice(0, -2) + (t.endsWith("AA") ? "BA" : "AA");
  const opts = { now };
  if (rnd() < 0.4) opts.audience = "api";
  if (rnd() < 0.4) opts.issuer = "https://id.example.com";
  if (rnd() < 0.3) opts.leeway = pick([0, 5, 60]);
  push("jwt", "verifyJwt", [t, S, opts]);
}
const SEGS = ["posts", "comments", "users", "billing", "read", "edit", "delete", "own", "*"];
for (let i = 0; i < 40; i++) {
  const perm = Array.from({ length: 1 + Math.floor(rnd() * 3) }, () => pick(SEGS.slice(0, 8))).join(".");
  push("can", "can", [POL, Array.from(new Set(Array.from({ length: Math.floor(rnd() * 3) }, () => pick(["viewer", "editor", "admin", "auditor"])))), perm]);
}

const doc = {
  format: "lombokauth-vectors-v1",
  specVersion: "0.1.0",
  note: "Normative cross-language vectors. Each case calls `fn` with `args` ({\"hex\": ...} denotes bytes); `expect` is {result} or {error: code}.",
  groups: [
    { name: "golden", cases: golden },
    { name: "generated-regression", cases: generated },
  ],
};
// ASCII-only file: non-ASCII characters are written as JSON \u escapes (UTF-16 code units).
const ascii = JSON.stringify(doc, null, 1).replace(/[\u0080-\uffff]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
writeFileSync(join(root, "vectors", "lombokauth-vectors-v1.json"), ascii + "\n");
const sha = createHash("sha256").update(readFileSync(join(root, "vectors", "lombokauth-vectors-v1.json"))).digest("hex");
console.log(`golden=${golden.length} generated=${generated.length} total=${golden.length + generated.length} sha256=${sha}`);
