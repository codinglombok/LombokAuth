// Zero-dependency primitives shared by the port: UTF-8, hex, base64, SHA-1, SHA-256, HMAC, PBKDF2
// and constant-time comparison. Verified against RFC test vectors and node:crypto in the tests.

export type Bytes = Uint8Array;

/** UTF-8 encoding; lone surrogates become U+FFFD (as `TextEncoder`). */
export function utf8(s: string): Bytes {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
        i++;
      } else c = 0xfffd;
    } else if (c >= 0xd800 && c <= 0xdfff) c = 0xfffd;
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return Uint8Array.from(out);
}

/** Strict UTF-8 decoding; returns null for malformed input. */
export function utf8Decode(b: Bytes): string | null {
  let s = "";
  for (let i = 0; i < b.length; ) {
    const x = b[i] as number;
    let cp: number;
    let n: number;
    if (x < 0x80) { cp = x; n = 1; }
    else if (x >= 0xc2 && x < 0xe0) { cp = x & 31; n = 2; }
    else if (x >= 0xe0 && x < 0xf0) { cp = x & 15; n = 3; }
    else if (x >= 0xf0 && x < 0xf5) { cp = x & 7; n = 4; }
    else return null;
    if (i + n > b.length) return null;
    for (let k = 1; k < n; k++) {
      const y = b[i + k] as number;
      if ((y & 0xc0) !== 0x80) return null;
      cp = (cp << 6) | (y & 63);
    }
    if ((n === 3 && (cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff))) || (n === 4 && (cp < 0x10000 || cp > 0x10ffff))) return null;
    s += String.fromCodePoint(cp);
    i += n;
  }
  return s;
}

const HEX = "0123456789abcdef";
export function toHex(b: Bytes): string {
  let s = "";
  for (const x of b) s += HEX[x >> 4]! + HEX[x & 15]!;
  return s;
}

/** Lowercase or uppercase hex with an even number of digits; null otherwise. */
export function fromHex(s: string): Bytes | null {
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function b64enc(b: Bytes, alpha: string, pad: boolean): string {
  let s = "";
  for (let i = 0; i < b.length; i += 3) {
    const n = ((b[i] as number) << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0);
    s += alpha[(n >> 18) & 63]! + alpha[(n >> 12) & 63]!;
    s += i + 1 < b.length ? alpha[(n >> 6) & 63]! : pad ? "=" : "";
    s += i + 2 < b.length ? alpha[n & 63]! : pad ? "=" : "";
  }
  return s;
}

/** Canonical decoding: rejects foreign characters, wrong padding and non-zero trailing bits. */
function b64dec(s: string, alpha: string, pad: boolean): Bytes | null {
  let body = s;
  if (pad) {
    if (s.length % 4 !== 0) return null;
    if (s.endsWith("==")) body = s.slice(0, -2);
    else if (s.endsWith("=")) body = s.slice(0, -1);
  }
  if (body.length % 4 === 1) return null;
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const ch of body) {
    const v = alpha.indexOf(ch);
    if (v < 0) return null;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 255);
    }
  }
  if ((acc & ((1 << bits) - 1)) !== 0) return null;
  return Uint8Array.from(out);
}

export const base64 = (b: Bytes): string => b64enc(b, B64, true);
export const base64Decode = (s: string): Bytes | null => b64dec(s, B64, true);
export const base64url = (b: Bytes): string => b64enc(b, B64URL, false);
export const base64urlDecode = (s: string): Bytes | null => b64dec(s, B64URL, false);

const K256 = Uint32Array.from([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function pad64(msg: Bytes): Bytes {
  const len = msg.length;
  const total = Math.ceil((len + 9) / 64) * 64;
  const p = new Uint8Array(total);
  p.set(msg);
  p[len] = 0x80;
  const bitsHi = Math.floor(len / 0x20000000);
  const bitsLo = (len * 8) >>> 0;
  const dv = new DataView(p.buffer);
  dv.setUint32(total - 8, bitsHi);
  dv.setUint32(total - 4, bitsLo);
  return p;
}

/** SHA-256 (FIPS 180-4). */
export function sha256(msg: Bytes): Bytes {
  const p = pad64(msg);
  const dv = new DataView(p.buffer);
  const h = Uint32Array.from([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const w = new Uint32Array(64);
  for (let off = 0; off < p.length; off += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(off + 4 * t);
    for (let t = 16; t < 64; t++) {
      const a = w[t - 15]!, b = w[t - 2]!;
      const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
      const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
      w[t] = (w[t - 16]! + s0 + w[t - 7]! + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = [h[0]!, h[1]!, h[2]!, h[3]!, h[4]!, h[5]!, h[6]!, h[7]!];
    for (let t = 0; t < 64; t++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K256[t]! + w[t]!) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0]! + a) >>> 0; h[1] = (h[1]! + b) >>> 0; h[2] = (h[2]! + c) >>> 0; h[3] = (h[3]! + d) >>> 0;
    h[4] = (h[4]! + e) >>> 0; h[5] = (h[5]! + f) >>> 0; h[6] = (h[6]! + g) >>> 0; h[7] = (h[7]! + hh) >>> 0;
  }
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) ov.setUint32(4 * i, h[i]!);
  return out;
}

/** SHA-1 (FIPS 180-4). Only for HOTP/TOTP interoperability; not for new designs. */
export function sha1(msg: Bytes): Bytes {
  const p = pad64(msg);
  const dv = new DataView(p.buffer);
  const h = Uint32Array.from([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]);
  const w = new Uint32Array(80);
  for (let off = 0; off < p.length; off += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(off + 4 * t);
    for (let t = 16; t < 80; t++) {
      const x = w[t - 3]! ^ w[t - 8]! ^ w[t - 14]! ^ w[t - 16]!;
      w[t] = (x << 1) | (x >>> 31);
    }
    let [a, b, c, d, e] = [h[0]!, h[1]!, h[2]!, h[3]!, h[4]!];
    for (let t = 0; t < 80; t++) {
      const f = t < 20 ? (b & c) | (~b & d) : t < 40 ? b ^ c ^ d : t < 60 ? (b & c) | (b & d) | (c & d) : b ^ c ^ d;
      const k = t < 20 ? 0x5a827999 : t < 40 ? 0x6ed9eba1 : t < 60 ? 0x8f1bbcdc : 0xca62c1d6;
      const tmp = (((a << 5) | (a >>> 27)) + f + e + k + w[t]!) >>> 0;
      e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = tmp;
    }
    h[0] = (h[0]! + a) >>> 0; h[1] = (h[1]! + b) >>> 0; h[2] = (h[2]! + c) >>> 0; h[3] = (h[3]! + d) >>> 0; h[4] = (h[4]! + e) >>> 0;
  }
  const out = new Uint8Array(20);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 5; i++) ov.setUint32(4 * i, h[i]!);
  return out;
}

/** HMAC (RFC 2104) over a 64-byte-block hash. */
export function hmac(hash: (m: Bytes) => Bytes, key: Bytes, msg: Bytes): Bytes {
  let k = key.length > 64 ? hash(key) : key;
  const block = new Uint8Array(64);
  block.set(k);
  const ipad = new Uint8Array(64 + msg.length);
  const opad = new Uint8Array(64 + (hash === sha1 ? 20 : 32));
  for (let i = 0; i < 64; i++) {
    ipad[i] = block[i]! ^ 0x36;
    opad[i] = block[i]! ^ 0x5c;
  }
  ipad.set(msg, 64);
  opad.set(hash(ipad), 64);
  k = hash(opad);
  return k;
}

export const hmacSha256 = (key: Bytes, msg: Bytes): Bytes => hmac(sha256, key, msg);
export const hmacSha1 = (key: Bytes, msg: Bytes): Bytes => hmac(sha1, key, msg);

/** PBKDF2-HMAC-SHA256 (RFC 8018). */
export function pbkdf2Sha256(password: Bytes, salt: Bytes, iterations: number, dkLen: number): Bytes {
  const out = new Uint8Array(dkLen);
  const blocks = Math.ceil(dkLen / 32);
  const s = new Uint8Array(salt.length + 4);
  s.set(salt);
  for (let i = 1; i <= blocks; i++) {
    new DataView(s.buffer).setUint32(salt.length, i);
    let u = hmacSha256(password, s);
    const t = u.slice();
    for (let j = 1; j < iterations; j++) {
      u = hmacSha256(password, u);
      for (let k = 0; k < 32; k++) t[k] = t[k]! ^ u[k]!;
    }
    out.set(t.subarray(0, Math.min(32, dkLen - (i - 1) * 32)), (i - 1) * 32);
  }
  return out;
}

/** Comparison whose duration depends only on the lengths. */
export function constantTimeEqual(a: Bytes, b: Bytes): boolean {
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) diff |= (a[i % (a.length || 1)] ?? 0) ^ (b[i % (b.length || 1)] ?? 0);
  return diff === 0;
}
