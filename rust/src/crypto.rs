//! Zero-dependency primitives: hex, base64, SHA-1, SHA-256, HMAC, PBKDF2 and constant-time
//! comparison. Verified against RFC test vectors in the test suite.

use alloc::string::String;
use alloc::vec::Vec;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex.
pub fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 15) as usize] as char);
    }
    s
}

/// Hex (either case, even length) to bytes.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    let val = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    b.chunks(2)
        .map(|p| Some(val(p[0])? << 4 | val(p[1])?))
        .collect()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64enc(b: &[u8], alpha: &[u8; 64], pad: bool) -> String {
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        s.push(alpha[(n >> 18 & 63) as usize] as char);
        s.push(alpha[(n >> 12 & 63) as usize] as char);
        if c.len() > 1 {
            s.push(alpha[(n >> 6 & 63) as usize] as char);
        } else if pad {
            s.push('=');
        }
        if c.len() > 2 {
            s.push(alpha[(n & 63) as usize] as char);
        } else if pad {
            s.push('=');
        }
    }
    s
}

fn b64dec(s: &str, alpha: &[u8; 64], pad: bool) -> Option<Vec<u8>> {
    let mut body = s.as_bytes();
    if pad {
        if body.len() % 4 != 0 {
            return None;
        }
        if body.ends_with(b"==") {
            body = &body[..body.len() - 2];
        } else if body.ends_with(b"=") {
            body = &body[..body.len() - 1];
        }
    }
    if body.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &ch in body {
        let v = alpha.iter().position(|&a| a == ch)? as u32;
        acc = (acc << 6 | v) & 0xffffff;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits & 255) as u8);
        }
    }
    if acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

/// Standard base64 with padding (RFC 4648 section 4).
pub fn base64(b: &[u8]) -> String {
    b64enc(b, B64, true)
}
/// Canonical standard base64 decoding.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    b64dec(s, B64, true)
}
/// base64url without padding (RFC 4648 section 5).
pub fn base64url(b: &[u8]) -> String {
    b64enc(b, B64URL, false)
}
/// Canonical base64url decoding (no padding, zero trailing bits).
pub fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    b64dec(s, B64URL, false)
}

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn pad64(msg: &[u8]) -> Vec<u8> {
    let mut p = msg.to_vec();
    p.push(0x80);
    while p.len() % 64 != 56 {
        p.push(0);
    }
    p.extend_from_slice(&((msg.len() as u64).wrapping_mul(8)).to_be_bytes());
    p
}

/// SHA-256 (FIPS 180-4).
pub fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut w = [0u32; 64];
    for block in pad64(msg).chunks(64) {
        for t in 0..16 {
            w[t] = u32::from_be_bytes([
                block[4 * t],
                block[4 * t + 1],
                block[4 * t + 2],
                block[4 * t + 3],
            ]);
        }
        for t in 16..64 {
            let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
            let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
            w[t] = w[t - 16]
                .wrapping_add(s0)
                .wrapping_add(w[t - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for t in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[t])
                .wrapping_add(w[t]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 32];
    for (i, x) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&x.to_be_bytes());
    }
    out
}

/// SHA-1 (FIPS 180-4). Only for HOTP/TOTP interoperability; not for new designs.
pub fn sha1(msg: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    let mut w = [0u32; 80];
    for block in pad64(msg).chunks(64) {
        for t in 0..16 {
            w[t] = u32::from_be_bytes([
                block[4 * t],
                block[4 * t + 1],
                block[4 * t + 2],
                block[4 * t + 3],
            ]);
        }
        for t in 16..80 {
            w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (t, wt) in w.iter().enumerate() {
            let (f, k) = match t {
                0..=19 => ((b & c) | (!b & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wt);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (i, x) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&x.to_be_bytes());
    }
    out
}

fn hmac_with(hash: fn(&[u8]) -> Vec<u8>, key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        let k = hash(key);
        block[..k.len()].copy_from_slice(&k);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend(block.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(msg);
    let ih = hash(&inner);
    let mut outer = Vec::with_capacity(64 + ih.len());
    outer.extend(block.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&ih);
    hash(&outer)
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let v = hmac_with(|m| sha256(m).to_vec(), key, msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// HMAC-SHA1 (RFC 2104).
pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let v = hmac_with(|m| sha1(m).to_vec(), key, msg);
    let mut out = [0u8; 20];
    out.copy_from_slice(&v);
    out
}

/// PBKDF2-HMAC-SHA256 (RFC 8018).
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(dk_len);
    let mut i: u32 = 1;
    while out.len() < dk_len {
        let mut s = salt.to_vec();
        s.extend_from_slice(&i.to_be_bytes());
        let mut u = hmac_sha256(password, &s);
        let mut t = u;
        for _ in 1..iterations {
            u = hmac_sha256(password, &u);
            for (x, y) in t.iter_mut().zip(u.iter()) {
                *x ^= y;
            }
        }
        let take = (dk_len - out.len()).min(32);
        out.extend_from_slice(&t[..take]);
        i += 1;
    }
    out
}

/// Comparison whose duration depends only on the lengths.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u32;
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = if a.is_empty() { 0 } else { a[i % a.len()] };
        let y = if b.is_empty() { 0 } else { b[i % b.len()] };
        diff |= (x ^ y) as u32;
    }
    diff == 0
}
