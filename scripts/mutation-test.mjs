// Mutation check for GP-11: inject a defect into the compiled TypeScript core and require the
// vector runner to fail. Usage (from repo root, after `npm test` built typescript/dist-test):
//   node scripts/mutation-test.mjs
import { cpSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const ts = join(root, "typescript");
const tmp = join(ts, ".mut");
const TARGET = "auth.js";
const MUTATIONS = [
  ["MIN_JWT_SECRET_BYTES = 32", "MIN_JWT_SECRET_BYTES = 16", "jwt secret length"],
  ['if (header["alg"] !== "HS256")', 'if (header["alg"] === "none")', "alg allow-list"],
  ['if (!HEADER_KEYS_SUPPORTED.includes(k))', "if (false)", "crit and unknown header parameters"],
  ["now >= claims[\"exp\"] + leeway", "now > claims[\"exp\"] + leeway", "exp boundary"],
  ["now + leeway < claims[\"nbf\"]", "now < claims[\"nbf\"]", "nbf leeway"],
  ["o[\"requireExp\"] ?? true", "o[\"requireExp\"] ?? false", "exp required by default"],
  ["!list.includes(o[\"audience\"])", "false", "audience check"],
  ["claims[\"iss\"] !== o[\"issuer\"]", "false", "issuer check"],
  ["if (!constantTimeEqual(hmacSha256(s, utf8(`${h}.${p}`)), sigBytes))", "if (false)", "signature check"],
  ["MIN_ITERATIONS = 1000", "MIN_ITERATIONS = 1", "minimum iterations"],
  ["MIN_SALT_BYTES = 16", "MIN_SALT_BYTES = 8", "minimum salt"],
  ["const PHC = /^\\$pbkdf2-sha256\\$i=([1-9][0-9]{0,7})", "const PHC = /^\\$pbkdf2-sha256\\$i=([0-9][0-9]{0,8})", "PHC iteration syntax"],
  ["return parsePhc(phc).n < n;", "return parsePhc(phc).n <= n;", "rehash comparison"],
  ["const off = mac[mac.length - 1] & 15;", "const off = 0;", "dynamic truncation"],
  ["& 0x7f) << 24)", "& 0xff) << 24)", "truncation sign bit"],
  ["Math.floor((timeSeconds - t0) / period)", "Math.floor(timeSeconds / period)", "t0 offset"],
  ["if (s < 0)", "if (false)", "negative steps skipped"],
  ["window < 0 || window > 10", "window < 0 || window > 100", "window cap"],
  ["if (b.length < 10)", "if (b.length < 1)", "OTP secret length"],
  ['/[A-Za-z0-9\\-._~]/', '/[A-Za-z0-9\\-._~@ ]/', "percent-encoding set"],
  ["if (s === \"*\" && i === a.length - 1)\n            return b.length >= a.length;", "if (s === \"*\" && i === a.length - 1)\n            return b.length > a.length;", "trailing star arity"],
  ["for (const d of deny)\n        if (matches(d, perm))\n            return false;", "", "deny wins"],
  ["for (const i of r.inherits)\n            stack.push(i);", "", "inheritance"],
  ["if (onPath.has(n))", "if (false)", "cycle detection"],
  ["[1, 3, 6].includes(s.length % 8)", "[1, 3].includes(s.length % 8)", "base32 lengths"],
];

const src = readFileSync(join(ts, "dist-test", "src", TARGET), "utf8");
let survived = 0;
for (const [find, repl, label] of MUTATIONS) {
  const count = src.split(find).length - 1;
  if (count === 0) { console.log(`SKIP     ${label}: pattern not found`); survived++; continue; }
  rmSync(tmp, { recursive: true, force: true });
  cpSync(join(ts, "dist-test"), tmp, { recursive: true });
  writeFileSync(join(tmp, "src", TARGET), src.split(find).join(repl));
  const r = spawnSync(process.execPath, ["--test", join(tmp, "test", "vectors.test.js")], { encoding: "utf8" });
  const killed = r.status !== 0;
  if (!killed) survived++;
  console.log(`${killed ? "KILLED  " : "SURVIVED"} ${label}`);
}
rmSync(tmp, { recursive: true, force: true });
console.log(`\n${MUTATIONS.length - survived}/${MUTATIONS.length} mutants killed`);
process.exit(survived === 0 ? 0 : 1);
