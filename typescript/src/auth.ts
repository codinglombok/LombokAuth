// LombokAuth core (TypeScript port). Normative behaviour: docs/SPEC_LombokAuth_v0.1.0.md.
// Pure functions: salts, secrets and the current time are supplied by the caller.
import {
  base64,
  base64Decode,
  base64url,
  base64urlDecode,
  constantTimeEqual,
  fromHex,
  hmacSha1,
  hmacSha256,
  pbkdf2Sha256,
  utf8,
  utf8Decode,
  type Bytes,
} from "./crypto.js";

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
export type JsonObject = { [k: string]: Json };

export type ErrorCode =
  | "invalid_secret"
  | "invalid_token"
  | "invalid_signature"
  | "unsupported_alg"
  | "token_expired"
  | "token_not_yet_valid"
  | "invalid_issuer"
  | "invalid_audience"
  | "invalid_claim"
  | "invalid_salt"
  | "invalid_hash"
  | "invalid_option"
  | "invalid_input"
  | "invalid_policy"
  | "invalid_role"
  | "invalid_permission";

export class LombokAuthError extends Error {
  readonly code: ErrorCode;
  readonly messageId: string;
  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = "LombokAuthError";
    this.code = code;
    this.messageId = `lombokauth.error.${code}`;
  }
}

const fail = (code: ErrorCode, message: string): never => {
  throw new LombokAuthError(code, message);
};

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const has = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);
const MAX_SAFE = 9007199254740991;
const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
const isSafeUint = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= MAX_SAFE;

function bytesOf(v: unknown, code: ErrorCode, what: string): Bytes {
  if (typeof v === "string") return utf8(v);
  if (v instanceof Uint8Array) return v;
  return fail(code, `${what} must be a string or bytes`);
}

function checkOptions(o: unknown, keys: string[]): Record<string, unknown> {
  if (o === undefined || o === null) return {};
  if (!isObject(o)) return fail("invalid_option", "options must be an object");
  for (const k of Object.keys(o)) if (!keys.includes(k)) fail("invalid_option", `unknown option: ${k}`);
  return o;
}

// ---------------------------------------------------------------- JWT (HS256)

export const MIN_JWT_SECRET_BYTES = 32;
const HEADER_KEYS_SUPPORTED = ["alg", "typ", "kid"];
const LONE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

function wellFormed(v: Json, depth: number): boolean {
  if (depth > 512) return false;
  if (typeof v === "number") return Number.isFinite(v);
  if (typeof v === "string") return !LONE.test(v);
  if (Array.isArray(v)) return v.every((x) => wellFormed(x, depth + 1));
  if (isObject(v)) return Object.keys(v).every((k) => !LONE.test(k) && wellFormed(v[k] as Json, depth + 1));
  return true;
}

function jwtSecret(secret: unknown): Bytes {
  const s = bytesOf(secret, "invalid_secret", "secret");
  if (s.length < MIN_JWT_SECRET_BYTES) return fail("invalid_secret", "HS256 secret must be at least 32 bytes");
  return s;
}

/** Sign `claims` as a compact JWS with header `{"alg":"HS256","typ":"JWT"}` (plus `kid` when given). */
export function signJwt(claims: unknown, secret: string | Bytes, options?: { kid?: string } | null): string {
  const s = jwtSecret(secret);
  const o = checkOptions(options, ["kid"]);
  if (!isObject(claims) || !wellFormed(claims as Json, 0)) return fail("invalid_claim", "claims must be a JSON object");
  const header: JsonObject = { alg: "HS256", typ: "JWT" };
  if (o["kid"] !== undefined) {
    if (typeof o["kid"] !== "string" || o["kid"] === "") return fail("invalid_option", "kid must be a non-empty string");
    header["kid"] = o["kid"];
  }
  const input = `${base64url(utf8(JSON.stringify(header)))}.${base64url(utf8(JSON.stringify(claims)))}`;
  return `${input}.${base64url(hmacSha256(s, utf8(input)))}`;
}

function decodeSegment(seg: string): JsonObject {
  const b = base64urlDecode(seg);
  if (b === null) return fail("invalid_token", "segment is not canonical base64url");
  const text = utf8Decode(b);
  if (text === null) return fail("invalid_token", "segment is not UTF-8");
  let v: Json;
  try {
    v = JSON.parse(text) as Json;
  } catch {
    return fail("invalid_token", "segment is not JSON");
  }
  if (!isObject(v) || !wellFormed(v, 0)) return fail("invalid_token", "segment is not a JSON object");
  return v as JsonObject;
}

function splitToken(token: unknown): [string, string, string] {
  if (typeof token !== "string") return fail("invalid_token", "token must be a string");
  const parts = token.split(".");
  if (parts.length !== 3) return fail("invalid_token", "token must have three segments");
  return parts as [string, string, string];
}

/** Header and claims WITHOUT verifying anything. Never use the result for authorization. */
export function decodeJwtUnverified(token: unknown): { header: JsonObject; claims: JsonObject } {
  const [h, p] = splitToken(token);
  return { header: decodeSegment(h), claims: decodeSegment(p) };
}

export interface VerifyOptions {
  /** Current time in seconds since the epoch (required). */
  now: number;
  /** Allowed clock skew in seconds (default 0). */
  leeway?: number;
  issuer?: string;
  audience?: string;
  /** Require an `exp` claim (default true). */
  requireExp?: boolean;
}

/**
 * Verify an HS256 token. Order: structure, header (`alg` must be HS256, no `crit`), signature,
 * claim types, `exp`, `nbf`, `iss`, `aud`. Throws with the first failing code.
 */
export function verifyJwt(token: unknown, secret: string | Bytes, options: VerifyOptions): { header: JsonObject; claims: JsonObject } {
  const s = jwtSecret(secret);
  const o = checkOptions(options, ["now", "leeway", "issuer", "audience", "requireExp"]);
  if (!isNum(o["now"])) return fail("invalid_option", "now must be a finite number of seconds");
  const now = o["now"] as number;
  const leeway = o["leeway"] === undefined ? 0 : (o["leeway"] as number);
  if (!isNum(leeway) || leeway < 0) return fail("invalid_option", "leeway must be a non-negative number");
  if (o["issuer"] !== undefined && typeof o["issuer"] !== "string") return fail("invalid_option", "issuer must be a string");
  if (o["audience"] !== undefined && typeof o["audience"] !== "string") return fail("invalid_option", "audience must be a string");
  if (o["requireExp"] !== undefined && typeof o["requireExp"] !== "boolean") return fail("invalid_option", "requireExp must be a boolean");
  const requireExp = (o["requireExp"] as boolean | undefined) ?? true;

  const [h, p, sig] = splitToken(token);
  const header = decodeSegment(h);
  const claims = decodeSegment(p);
  const sigBytes = base64urlDecode(sig);
  if (sigBytes === null) return fail("invalid_token", "signature is not canonical base64url");
  if (header["alg"] !== "HS256") return fail("unsupported_alg", "only HS256 is accepted");
  for (const k of Object.keys(header)) if (!HEADER_KEYS_SUPPORTED.includes(k)) return fail("invalid_token", `unsupported header parameter: ${k}`);
  if (header["typ"] !== undefined && header["typ"] !== "JWT") return fail("invalid_token", "typ must be JWT");
  if (header["kid"] !== undefined && typeof header["kid"] !== "string") return fail("invalid_token", "kid must be a string");
  if (!constantTimeEqual(hmacSha256(s, utf8(`${h}.${p}`)), sigBytes)) return fail("invalid_signature", "signature does not match");

  for (const k of ["exp", "nbf", "iat"]) if (claims[k] !== undefined && !isNum(claims[k])) return fail("invalid_claim", `${k} must be a number`);
  if (claims["iss"] !== undefined && typeof claims["iss"] !== "string") return fail("invalid_claim", "iss must be a string");
  if (claims["sub"] !== undefined && typeof claims["sub"] !== "string") return fail("invalid_claim", "sub must be a string");
  const aud = claims["aud"];
  if (aud !== undefined && typeof aud !== "string" && !(Array.isArray(aud) && aud.every((x) => typeof x === "string"))) return fail("invalid_claim", "aud must be a string or an array of strings");
  if (claims["exp"] === undefined) {
    if (requireExp) return fail("invalid_claim", "exp is required");
  } else if (now >= (claims["exp"] as number) + leeway) return fail("token_expired", "token has expired");
  if (claims["nbf"] !== undefined && now + leeway < (claims["nbf"] as number)) return fail("token_not_yet_valid", "token is not valid yet");
  if (o["issuer"] !== undefined && claims["iss"] !== o["issuer"]) return fail("invalid_issuer", "issuer does not match");
  if (o["audience"] !== undefined) {
    const list = aud === undefined ? [] : typeof aud === "string" ? [aud] : (aud as string[]);
    if (!list.includes(o["audience"] as string)) return fail("invalid_audience", "audience does not match");
  }
  return { header, claims };
}

// ---------------------------------------------------------------- password hashing (PBKDF2, PHC format)

export const DEFAULT_ITERATIONS = 600000;
export const MIN_ITERATIONS = 1000;
export const MAX_ITERATIONS = 10000000;
export const MIN_SALT_BYTES = 16;
const PHC = /^\$pbkdf2-sha256\$i=([1-9][0-9]{0,7})\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/;

const b64nopad = (b: Bytes): string => base64(b).replace(/=+$/, "");
function b64nopadDecode(s: string): Bytes | null {
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  if (s.length % 4 === 1) return null;
  return base64Decode(padded);
}

function iterationsOf(v: unknown): number {
  if (v === undefined) return DEFAULT_ITERATIONS;
  if (typeof v !== "number" || !Number.isInteger(v) || v < MIN_ITERATIONS || v > MAX_ITERATIONS) return fail("invalid_option", "iterations must be an integer in 1000..10000000");
  return v;
}

/** PHC string `$pbkdf2-sha256$i=<n>$<salt>$<hash>` (standard base64 without padding, 32-byte hash). */
export function hashPassword(password: string, salt: Bytes | string, iterations?: number): string {
  if (typeof password !== "string") return fail("invalid_input", "password must be a string");
  let s: Bytes;
  if (typeof salt === "string") {
    const b = fromHex(salt);
    if (b === null) return fail("invalid_salt", "salt must be bytes or hex");
    s = b;
  } else if (salt instanceof Uint8Array) s = salt;
  else return fail("invalid_salt", "salt must be bytes or hex");
  if (s.length < MIN_SALT_BYTES) return fail("invalid_salt", "salt must be at least 16 bytes");
  const n = iterationsOf(iterations);
  return `$pbkdf2-sha256$i=${n}$${b64nopad(s)}$${b64nopad(pbkdf2Sha256(utf8(password), s, n, 32))}`;
}

function parsePhc(phc: unknown): { n: number; salt: Bytes; hash: Bytes } {
  if (typeof phc !== "string") return fail("invalid_hash", "hash must be a string");
  const m = PHC.exec(phc);
  if (m === null) return fail("invalid_hash", "unsupported or malformed PHC string");
  const n = Number(m[1]);
  if (n < MIN_ITERATIONS || n > MAX_ITERATIONS) return fail("invalid_hash", "iteration count outside 1000..10000000");
  const salt = b64nopadDecode(m[2] as string);
  const hash = b64nopadDecode(m[3] as string);
  if (salt === null || hash === null || salt.length < MIN_SALT_BYTES || hash.length !== 32) return fail("invalid_hash", "salt or hash has the wrong encoding or length");
  if (b64nopad(salt) !== m[2] || b64nopad(hash) !== m[3]) return fail("invalid_hash", "salt or hash is not canonical base64");
  return { n, salt, hash };
}

/** True when `password` matches the PHC string. Malformed strings throw `invalid_hash`. */
export function verifyPassword(password: string, phc: string): boolean {
  const p = parsePhc(phc);
  if (typeof password !== "string") return fail("invalid_input", "password must be a string");
  return constantTimeEqual(pbkdf2Sha256(utf8(password), p.salt, p.n, 32), p.hash);
}

/** True when the stored hash uses fewer iterations than `iterations` (default 600000). */
export function needsRehash(phc: string, iterations?: number): boolean {
  const n = iterationsOf(iterations);
  return parsePhc(phc).n < n;
}

/** Convenience: hash with a fresh 16-byte salt from `crypto.getRandomValues`. */
export function hashPasswordRandom(password: string, iterations?: number): string {
  const c = (globalThis as { crypto?: { getRandomValues(a: Uint8Array): Uint8Array } }).crypto;
  if (!c || typeof c.getRandomValues !== "function") return fail("invalid_option", "no secure random source (crypto.getRandomValues) is available");
  return hashPassword(password, c.getRandomValues(new Uint8Array(16)), iterations);
}

// ---------------------------------------------------------------- base32, HOTP, TOTP

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** RFC 4648 base32 with padding. */
export function base32Encode(data: Bytes | string): string {
  const b = bytesOf(data, "invalid_input", "data");
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const x of b) {
    acc = ((acc << 8) | x) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32[(acc >> bits) & 31];
    }
  }
  if (bits > 0) out += B32[(acc << (5 - bits)) & 31];
  while (out.length % 8 !== 0) out += "=";
  return out;
}

/** RFC 4648 base32 decoding; case-insensitive, padding optional, canonical trailing bits. */
export function base32Decode(text: string): Bytes {
  if (typeof text !== "string") return fail("invalid_input", "text must be a string");
  const s = text.replace(/[a-z]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 32)).replace(/=+$/, "");
  if (text.length !== s.length && text.length % 8 !== 0) return fail("invalid_input", "invalid base32 padding");
  if ([1, 3, 6].includes(s.length % 8)) return fail("invalid_input", "invalid base32 length");
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const ch of s) {
    const v = B32.indexOf(ch);
    if (v < 0) return fail("invalid_input", "invalid base32 character");
    acc = ((acc << 5) | v) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 255);
    }
  }
  if ((acc & ((1 << bits) - 1)) !== 0) return fail("invalid_input", "non-zero trailing bits");
  return Uint8Array.from(out);
}

export type OtpAlgorithm = "SHA1" | "SHA256";

function otpSecret(secret: unknown): Bytes {
  const b = bytesOf(secret, "invalid_secret", "secret");
  if (b.length < 10) return fail("invalid_secret", "OTP secret must be at least 10 bytes (80 bits)");
  return b;
}

function otpOptions(options: unknown, keys: string[]): { digits: number; algorithm: OtpAlgorithm; o: Record<string, unknown> } {
  const o = checkOptions(options, keys);
  const digits = o["digits"] === undefined ? 6 : o["digits"];
  if (typeof digits !== "number" || !Number.isInteger(digits) || digits < 6 || digits > 8) return fail("invalid_option", "digits must be 6, 7 or 8");
  const algorithm = o["algorithm"] === undefined ? "SHA1" : o["algorithm"];
  if (algorithm !== "SHA1" && algorithm !== "SHA256") return fail("invalid_option", "algorithm must be SHA1 or SHA256");
  return { digits, algorithm, o };
}

function hotpRaw(key: Bytes, counter: number, digits: number, algorithm: OtpAlgorithm): string {
  const msg = new Uint8Array(8);
  const dv = new DataView(msg.buffer);
  dv.setUint32(0, Math.floor(counter / 4294967296));
  dv.setUint32(4, counter >>> 0);
  const mac = algorithm === "SHA1" ? hmacSha1(key, msg) : hmacSha256(key, msg);
  const off = (mac[mac.length - 1] as number) & 15;
  const bin = (((mac[off] as number) & 0x7f) << 24) | ((mac[off + 1] as number) << 16) | ((mac[off + 2] as number) << 8) | (mac[off + 3] as number);
  return String(bin % 10 ** digits).padStart(digits, "0");
}

/** RFC 4226 HOTP. */
export function hotp(secret: Bytes | string, counter: number, options?: { digits?: number; algorithm?: OtpAlgorithm } | null): string {
  const key = otpSecret(secret);
  const { digits, algorithm } = otpOptions(options, ["digits", "algorithm"]);
  if (!isSafeUint(counter)) return fail("invalid_option", "counter must be an integer in 0..2^53-1");
  return hotpRaw(key, counter, digits, algorithm);
}

export interface TotpOptions {
  period?: number;
  digits?: number;
  algorithm?: OtpAlgorithm;
  t0?: number;
}

function totpStep(timeSeconds: unknown, o: Record<string, unknown>): { step: number; period: number } {
  const period = o["period"] === undefined ? 30 : o["period"];
  if (typeof period !== "number" || !Number.isInteger(period) || period < 1 || period > 86400) return fail("invalid_option", "period must be an integer in 1..86400");
  const t0 = o["t0"] === undefined ? 0 : o["t0"];
  if (!isSafeUint(t0)) return fail("invalid_option", "t0 must be a non-negative integer");
  if (!isSafeUint(timeSeconds)) return fail("invalid_option", "time must be a non-negative integer number of seconds");
  if (timeSeconds < t0) return fail("invalid_option", "time is before t0");
  return { step: Math.floor((timeSeconds - t0) / period), period };
}

/** RFC 6238 TOTP for a time in seconds. */
export function totp(secret: Bytes | string, timeSeconds: number, options?: TotpOptions | null): string {
  const key = otpSecret(secret);
  const { digits, algorithm, o } = otpOptions(options, ["period", "digits", "algorithm", "t0"]);
  const { step } = totpStep(timeSeconds, o);
  return hotpRaw(key, step, digits, algorithm);
}

/**
 * Check `code` against the steps `step - window .. step + window` (window default 1, max 10).
 * Returns the matching step offset (for replay tracking) or `null`. Comparison is constant-time
 * per candidate.
 */
export function verifyTotp(secret: Bytes | string, code: unknown, timeSeconds: number, options?: (TotpOptions & { window?: number }) | null): number | null {
  const key = otpSecret(secret);
  const { digits, algorithm, o } = otpOptions(options, ["period", "digits", "algorithm", "t0", "window"]);
  const { step } = totpStep(timeSeconds, o);
  const window = o["window"] === undefined ? 1 : o["window"];
  if (typeof window !== "number" || !Number.isInteger(window) || window < 0 || window > 10) return fail("invalid_option", "window must be an integer in 0..10");
  if (typeof code !== "string" || code.length !== digits || !/^[0-9]+$/.test(code)) return null;
  let found: number | null = null;
  for (let d = -window; d <= window; d++) {
    const s = step + d;
    if (s < 0) continue;
    if (constantTimeEqual(utf8(hotpRaw(key, s, digits, algorithm)), utf8(code)) && found === null) found = d;
  }
  return found;
}

function pctEncode(s: string): string {
  let out = "";
  for (const b of utf8(s)) {
    const c = String.fromCharCode(b);
    out += /[A-Za-z0-9\-._~]/.test(c) ? c : "%" + b.toString(16).toUpperCase().padStart(2, "0");
  }
  return out;
}

/** `otpauth://totp/...` URI for authenticator apps (Key Uri Format). */
export function otpauthUri(secret: Bytes | string, account: string, issuer: string, options?: { period?: number; digits?: number; algorithm?: OtpAlgorithm } | null): string {
  const key = otpSecret(secret);
  const { digits, algorithm, o } = otpOptions(options, ["period", "digits", "algorithm"]);
  const period = o["period"] === undefined ? 30 : o["period"];
  if (typeof period !== "number" || !Number.isInteger(period) || period < 1 || period > 86400) return fail("invalid_option", "period must be an integer in 1..86400");
  if (typeof account !== "string" || account === "" || account.includes(":")) return fail("invalid_input", "account must be a non-empty string without ':'");
  if (typeof issuer !== "string" || issuer === "" || issuer.includes(":")) return fail("invalid_input", "issuer must be a non-empty string without ':'");
  const secret32 = base32Encode(key).replace(/=+$/, "");
  return `otpauth://totp/${pctEncode(issuer)}:${pctEncode(account)}?secret=${secret32}&issuer=${pctEncode(issuer)}&algorithm=${algorithm}&digits=${digits}&period=${period}`;
}

// ---------------------------------------------------------------- RBAC

const ROLE = /^[A-Za-z0-9_.-]{1,64}$/;
export const MAX_INHERITANCE = 64;
const SEGMENT = /^[A-Za-z0-9_-]+$/;

function checkPattern(p: unknown, allowWildcard: boolean): string {
  if (typeof p !== "string") return fail("invalid_permission", "permission must be a string");
  const segs = p.split(".");
  for (const s of segs) {
    if (s === "*" && allowWildcard) continue;
    if (!SEGMENT.test(s)) return fail("invalid_permission", "permission segments are [A-Za-z0-9_-]+ (or * in patterns)");
  }
  return p;
}

/** Does pattern `p` (with `*` segments) match permission `perm`? A trailing `*` matches one or more segments. */
function matches(p: string, perm: string): boolean {
  const a = p.split(".");
  const b = perm.split(".");
  for (let i = 0; i < a.length; i++) {
    const s = a[i] as string;
    if (s === "*" && i === a.length - 1) return b.length >= a.length;
    if (i >= b.length) return false;
    if (s !== "*" && s !== b[i]) return false;
  }
  return a.length === b.length;
}

interface Role {
  allow: string[];
  deny: string[];
  inherits: string[];
}

function parsePolicy(policy: unknown): Map<string, Role> {
  if (!isObject(policy)) return fail("invalid_policy", "policy must be an object");
  for (const k of Object.keys(policy)) if (k !== "roles") fail("invalid_policy", `unknown policy key: ${k}`);
  const roles = policy["roles"];
  if (!isObject(roles)) return fail("invalid_policy", "policy.roles must be an object");
  const out = new Map<string, Role>();
  for (const name of Object.keys(roles)) {
    if (!ROLE.test(name)) fail("invalid_policy", `invalid role name: ${name}`);
    const r = roles[name];
    if (!isObject(r)) return fail("invalid_policy", "role must be an object");
    for (const k of Object.keys(r)) if (k !== "permissions" && k !== "inherits") fail("invalid_policy", `unknown role key: ${k}`);
    const perms = r["permissions"] ?? [];
    const inh = r["inherits"] ?? [];
    if (!Array.isArray(perms) || !Array.isArray(inh)) return fail("invalid_policy", "permissions and inherits must be arrays");
    const role: Role = { allow: [], deny: [], inherits: [] };
    for (const p of perms) {
      if (typeof p !== "string") fail("invalid_permission", "permission must be a string");
      const deny = (p as string).startsWith("!");
      const pat = checkPattern(deny ? (p as string).slice(1) : p, true);
      (deny ? role.deny : role.allow).push(pat);
    }
    for (const i of inh) {
      if (typeof i !== "string" || !ROLE.test(i)) fail("invalid_policy", "inherits must list role names");
      role.inherits.push(i as string);
    }
    out.set(name, role);
  }
  for (const [, r] of out) for (const i of r.inherits) if (!out.has(i)) fail("invalid_policy", `unknown inherited role: ${i}`);
  // Cycle detection and chain length: height(role) = 1 + max(height(inherited)); must be <= 64.
  const height = new Map<string, number>();
  const onPath = new Set<string>();
  const visit = (n: string): number => {
    const known = height.get(n);
    if (known !== undefined) return known;
    if (onPath.has(n)) return fail("invalid_policy", "inheritance cycle");
    if (onPath.size >= MAX_INHERITANCE) return fail("invalid_policy", "inheritance chain is longer than 64");
    onPath.add(n);
    let h = 1;
    for (const i of out.get(n)!.inherits) h = Math.max(h, 1 + visit(i));
    onPath.delete(n);
    if (h > MAX_INHERITANCE) return fail("invalid_policy", "inheritance chain is longer than 64");
    height.set(n, h);
    return h;
  };
  for (const n of out.keys()) visit(n);
  return out;
}

function collect(policy: Map<string, Role>, roles: unknown): { allow: Set<string>; deny: Set<string> } {
  if (!Array.isArray(roles)) return fail("invalid_role", "roles must be an array");
  const allow = new Set<string>();
  const deny = new Set<string>();
  const seen = new Set<string>();
  const stack: string[] = [];
  for (const r of roles) {
    if (typeof r !== "string" || !policy.has(r)) return fail("invalid_role", `unknown role: ${String(r)}`);
    stack.push(r);
  }
  while (stack.length > 0) {
    const n = stack.pop() as string;
    if (seen.has(n)) continue;
    seen.add(n);
    const r = policy.get(n)!;
    for (const p of r.allow) allow.add(p);
    for (const p of r.deny) deny.add(p);
    for (const i of r.inherits) stack.push(i);
  }
  return { allow, deny };
}

/** Validate a policy document; returns true or throws. */
export function validatePolicy(policy: unknown): true {
  parsePolicy(policy);
  return true;
}

/** True when some role (with inheritance) allows `permission` and no role denies it. Deny wins. */
export function can(policy: unknown, roles: unknown, permission: unknown): boolean {
  const p = parsePolicy(policy);
  const { allow, deny } = collect(p, roles);
  const perm = checkPattern(permission, false);
  for (const d of deny) if (matches(d, perm)) return false;
  for (const a of allow) if (matches(a, perm)) return true;
  return false;
}

/** Effective patterns for a set of roles (sorted by UTF-16 code unit order, duplicates removed). */
export function effectivePermissions(policy: unknown, roles: unknown): { allow: string[]; deny: string[] } {
  const { allow, deny } = collect(parsePolicy(policy), roles);
  const sort = (s: Set<string>): string[] => [...s].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
  return { allow: sort(allow), deny: sort(deny) };
}

// ---------------------------------------------------------------- contract entry point

function argBytes(v: unknown): unknown {
  if (isObject(v) && typeof v["hex"] === "string" && Object.keys(v).length === 1) {
    const b = fromHex(v["hex"] as string);
    if (b === null) return fail("invalid_input", "invalid hex");
    return b;
  }
  return v;
}

/** Dynamic entry point with the contract's JSON calling convention; `{ "hex": "..." }` denotes bytes. */
export function call(fn: string, args: unknown[]): unknown {
  const a = (i: number): unknown => args[i];
  switch (fn) {
    case "signJwt": return signJwt(a(0), argBytes(a(1)) as string, a(2) as { kid?: string } | null);
    case "verifyJwt": return verifyJwt(a(0), argBytes(a(1)) as string, a(2) as VerifyOptions);
    case "decodeJwtUnverified": return decodeJwtUnverified(a(0));
    case "hashPassword": return hashPassword(a(0) as string, argBytes(a(1)) as string, a(2) as number | undefined);
    case "verifyPassword": return verifyPassword(a(0) as string, a(1) as string);
    case "needsRehash": return needsRehash(a(0) as string, a(1) as number | undefined);
    case "base32Encode": return base32Encode(argBytes(a(0)) as string);
    case "base32Decode": return { hex: Array.from(base32Decode(a(0) as string), (x) => x.toString(16).padStart(2, "0")).join("") };
    case "hotp": return hotp(argBytes(a(0)) as string, a(1) as number, a(2) as null);
    case "totp": return totp(argBytes(a(0)) as string, a(1) as number, a(2) as null);
    case "verifyTotp": return verifyTotp(argBytes(a(0)) as string, a(1), a(2) as number, a(3) as null);
    case "otpauthUri": return otpauthUri(argBytes(a(0)) as string, a(1) as string, a(2) as string, a(3) as null);
    case "validatePolicy": return validatePolicy(a(0));
    case "can": return can(a(0), a(1), a(2));
    case "effectivePermissions": return effectivePermissions(a(0), a(1));
    default: return fail("invalid_option", `unknown function: ${fn}`);
  }
}
