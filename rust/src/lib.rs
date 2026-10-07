//! LombokAuth core (Rust reference, `no_std + alloc`, zero dependencies).
//!
//! JWT HS256, PBKDF2-SHA256 password hashes in PHC format, HOTP and TOTP, and role-based access
//! control with wildcards and deny rules. Output is identical to the other ports for every vector
//! in `vectors/lombokauth-vectors-v1.json`; the normative contract is
//! `docs/SPEC_LombokAuth_v0.1.0.md`. Salts, secrets and time are supplied by the caller.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod crypto;
pub mod json;

pub use json::{parse_json, Value};

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

const MAX_SAFE: f64 = 9007199254740991.0;

/// Error with a canonical `code` (contract) and an English message (not normative).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub code: &'static str,
    pub message: String,
}

impl Error {
    fn new(code: &'static str, message: &str) -> Self {
        Error {
            code,
            message: message.to_string(),
        }
    }
    /// Stable message id for translation through LombokLocale.
    pub fn message_id(&self) -> String {
        format!("lombokauth.error.{}", self.code)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

fn e(code: &'static str, m: &str) -> Error {
    Error::new(code, m)
}

fn finite_tree(v: &Value) -> bool {
    match v {
        Value::Num(n) => n.is_finite(),
        Value::Arr(a) => a.iter().all(finite_tree),
        Value::Obj(m) => m.iter().all(|(_, x)| finite_tree(x)),
        _ => true,
    }
}

fn safe_uint(v: &Value) -> Option<u64> {
    match v {
        Value::Num(n) if (0.0..=MAX_SAFE).contains(n) && *n == (*n as u64) as f64 => {
            Some(*n as u64)
        }
        _ => None,
    }
}

fn check_keys(o: Option<&Value>, keys: &[&str]) -> Result<Value> {
    match o {
        None | Some(Value::Null) => Ok(Value::Obj(Vec::new())),
        Some(v @ Value::Obj(m)) => {
            for (k, _) in m {
                if !keys.contains(&k.as_str()) {
                    return Err(e("invalid_option", "unknown option"));
                }
            }
            Ok(v.clone())
        }
        Some(_) => Err(e("invalid_option", "options must be an object")),
    }
}

// ---------------------------------------------------------------- JWT (HS256)

/// Minimum HS256 secret length in bytes (RFC 7518 section 3.2).
pub const MIN_JWT_SECRET_BYTES: usize = 32;

fn jwt_secret(s: &[u8]) -> Result<()> {
    if s.len() < MIN_JWT_SECRET_BYTES {
        return Err(e(
            "invalid_secret",
            "HS256 secret must be at least 32 bytes",
        ));
    }
    Ok(())
}

/// Sign `claims` (a JSON object) as a compact JWS with header `{"alg":"HS256","typ":"JWT"}`
/// plus `kid` when given.
pub fn sign_jwt(claims: &Value, secret: &[u8], kid: Option<&str>) -> Result<String> {
    jwt_secret(secret)?;
    if claims.as_obj().is_none() || !finite_tree(claims) {
        return Err(e("invalid_claim", "claims must be a JSON object"));
    }
    let mut header = Value::Obj(Vec::new());
    header.set("alg", Value::Str("HS256".into()));
    header.set("typ", Value::Str("JWT".into()));
    if let Some(k) = kid {
        if k.is_empty() {
            return Err(e("invalid_option", "kid must be a non-empty string"));
        }
        header.set("kid", Value::Str(k.into()));
    }
    let input = format!(
        "{}.{}",
        crypto::base64url(header.to_json().as_bytes()),
        crypto::base64url(claims.to_json().as_bytes())
    );
    let sig = crypto::base64url(&crypto::hmac_sha256(secret, input.as_bytes()));
    Ok(format!("{}.{}", input, sig))
}

fn decode_segment(seg: &str) -> Result<Value> {
    let b = crypto::base64url_decode(seg)
        .ok_or_else(|| e("invalid_token", "segment is not canonical base64url"))?;
    let text = String::from_utf8(b).map_err(|_| e("invalid_token", "segment is not UTF-8"))?;
    let v = parse_json(&text).map_err(|_| e("invalid_token", "segment is not JSON"))?;
    if v.as_obj().is_none() || !finite_tree(&v) {
        return Err(e("invalid_token", "segment is not a JSON object"));
    }
    Ok(v)
}

fn split_token(token: &str) -> Result<(&str, &str, &str)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(e("invalid_token", "token must have three segments"));
    }
    Ok((parts[0], parts[1], parts[2]))
}

/// Header and claims WITHOUT verifying anything. Never use the result for authorization.
pub fn decode_jwt_unverified(token: &str) -> Result<(Value, Value)> {
    let (h, p, _) = split_token(token)?;
    Ok((decode_segment(h)?, decode_segment(p)?))
}

/// Verification options.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyOptions {
    /// Current time in seconds since the epoch.
    pub now: f64,
    /// Allowed clock skew in seconds.
    pub leeway: f64,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub require_exp: bool,
}

impl VerifyOptions {
    pub fn at(now: f64) -> Self {
        VerifyOptions {
            now,
            leeway: 0.0,
            issuer: None,
            audience: None,
            require_exp: true,
        }
    }
}

/// Verify an HS256 token and return `(header, claims)`.
pub fn verify_jwt(token: &str, secret: &[u8], o: &VerifyOptions) -> Result<(Value, Value)> {
    jwt_secret(secret)?;
    if !o.now.is_finite() {
        return Err(e(
            "invalid_option",
            "now must be a finite number of seconds",
        ));
    }
    if !o.leeway.is_finite() || o.leeway < 0.0 {
        return Err(e("invalid_option", "leeway must be a non-negative number"));
    }
    let (h, p, sig) = split_token(token)?;
    let header = decode_segment(h)?;
    let claims = decode_segment(p)?;
    let sig_bytes = crypto::base64url_decode(sig)
        .ok_or_else(|| e("invalid_token", "signature is not canonical base64url"))?;
    if header.get("alg").and_then(|a| a.as_str()) != Some("HS256") {
        return Err(e("unsupported_alg", "only HS256 is accepted"));
    }
    for (k, _) in header.as_obj().map(|m| m.as_slice()).unwrap_or(&[]) {
        if !["alg", "typ", "kid"].contains(&k.as_str()) {
            return Err(e("invalid_token", "unsupported header parameter"));
        }
    }
    if let Some(t) = header.get("typ") {
        if t.as_str() != Some("JWT") {
            return Err(e("invalid_token", "typ must be JWT"));
        }
    }
    if let Some(k) = header.get("kid") {
        if k.as_str().is_none() {
            return Err(e("invalid_token", "kid must be a string"));
        }
    }
    let mac = crypto::hmac_sha256(secret, format!("{}.{}", h, p).as_bytes());
    if !crypto::constant_time_eq(&mac, &sig_bytes) {
        return Err(e("invalid_signature", "signature does not match"));
    }
    for k in ["exp", "nbf", "iat"] {
        if let Some(v) = claims.get(k) {
            if v.as_f64().is_none() {
                return Err(e("invalid_claim", "numeric date claim must be a number"));
            }
        }
    }
    for k in ["iss", "sub"] {
        if let Some(v) = claims.get(k) {
            if v.as_str().is_none() {
                return Err(e("invalid_claim", "iss and sub must be strings"));
            }
        }
    }
    let aud = claims.get("aud");
    if let Some(a) = aud {
        let okay = match a {
            Value::Str(_) => true,
            Value::Arr(items) => items.iter().all(|x| x.as_str().is_some()),
            _ => false,
        };
        if !okay {
            return Err(e(
                "invalid_claim",
                "aud must be a string or an array of strings",
            ));
        }
    }
    match claims.get("exp").and_then(|v| v.as_f64()) {
        None => {
            if o.require_exp {
                return Err(e("invalid_claim", "exp is required"));
            }
        }
        Some(exp) => {
            if o.now >= exp + o.leeway {
                return Err(e("token_expired", "token has expired"));
            }
        }
    }
    if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_f64()) {
        if o.now + o.leeway < nbf {
            return Err(e("token_not_yet_valid", "token is not valid yet"));
        }
    }
    if let Some(iss) = &o.issuer {
        if claims.get("iss").and_then(|v| v.as_str()) != Some(iss.as_str()) {
            return Err(e("invalid_issuer", "issuer does not match"));
        }
    }
    if let Some(want) = &o.audience {
        let found = match aud {
            Some(Value::Str(s)) => s == want,
            Some(Value::Arr(items)) => items.iter().any(|x| x.as_str() == Some(want.as_str())),
            _ => false,
        };
        if !found {
            return Err(e("invalid_audience", "audience does not match"));
        }
    }
    Ok((header, claims))
}

// ---------------------------------------------------------------- password hashing

pub const DEFAULT_ITERATIONS: u32 = 600000;
pub const MIN_ITERATIONS: u32 = 1000;
pub const MAX_ITERATIONS: u32 = 10000000;
pub const MIN_SALT_BYTES: usize = 16;

fn b64nopad(b: &[u8]) -> String {
    crypto::base64(b).trim_end_matches('=').to_string()
}

fn b64nopad_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 4 == 1 {
        return None;
    }
    let mut padded = String::from(s);
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    crypto::base64_decode(&padded)
}

fn check_iterations(n: u32) -> Result<u32> {
    if (MIN_ITERATIONS..=MAX_ITERATIONS).contains(&n) {
        Ok(n)
    } else {
        Err(e(
            "invalid_option",
            "iterations must be an integer in 1000..10000000",
        ))
    }
}

/// PHC string `$pbkdf2-sha256$i=<n>$<salt>$<hash>` (standard base64 without padding, 32-byte hash).
pub fn hash_password(password: &str, salt: &[u8], iterations: u32) -> Result<String> {
    if salt.len() < MIN_SALT_BYTES {
        return Err(e("invalid_salt", "salt must be at least 16 bytes"));
    }
    let n = check_iterations(iterations)?;
    let h = crypto::pbkdf2_sha256(password.as_bytes(), salt, n, 32);
    Ok(format!(
        "$pbkdf2-sha256$i={}${}${}",
        n,
        b64nopad(salt),
        b64nopad(&h)
    ))
}

struct Phc {
    n: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

fn is_b64_body(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

fn parse_phc(phc: &str) -> Result<Phc> {
    let bad = || e("invalid_hash", "unsupported or malformed PHC string");
    let rest = phc.strip_prefix("$pbkdf2-sha256$i=").ok_or_else(bad)?;
    let parts: Vec<&str> = rest.split('$').collect();
    if parts.len() != 3 {
        return Err(bad());
    }
    let (ns, salt_s, hash_s) = (parts[0], parts[1], parts[2]);
    if ns.is_empty()
        || ns.len() > 8
        || ns.starts_with('0')
        || !ns.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(bad());
    }
    if !is_b64_body(salt_s) || !is_b64_body(hash_s) {
        return Err(bad());
    }
    let n: u32 = ns.parse().map_err(|_| bad())?;
    if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&n) {
        return Err(e("invalid_hash", "iteration count outside 1000..10000000"));
    }
    let wrong = || {
        e(
            "invalid_hash",
            "salt or hash has the wrong encoding or length",
        )
    };
    let salt = b64nopad_decode(salt_s).ok_or_else(wrong)?;
    let hash = b64nopad_decode(hash_s).ok_or_else(wrong)?;
    if salt.len() < MIN_SALT_BYTES || hash.len() != 32 {
        return Err(wrong());
    }
    if b64nopad(&salt) != salt_s || b64nopad(&hash) != hash_s {
        return Err(e("invalid_hash", "salt or hash is not canonical base64"));
    }
    Ok(Phc { n, salt, hash })
}

/// True when `password` matches the PHC string. Malformed strings give `invalid_hash`.
pub fn verify_password(password: &str, phc: &str) -> Result<bool> {
    let p = parse_phc(phc)?;
    let h = crypto::pbkdf2_sha256(password.as_bytes(), &p.salt, p.n, 32);
    Ok(crypto::constant_time_eq(&h, &p.hash))
}

/// True when the stored hash uses fewer iterations than `iterations`.
pub fn needs_rehash(phc: &str, iterations: u32) -> Result<bool> {
    let n = check_iterations(iterations)?;
    Ok(parse_phc(phc)?.n < n)
}

// ---------------------------------------------------------------- base32, HOTP, TOTP

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 with padding.
pub fn base32_encode(b: &[u8]) -> String {
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &x in b {
        acc = ((acc << 8) | x as u32) & 0xffff;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    while out.len() % 8 != 0 {
        out.push('=');
    }
    out
}

/// RFC 4648 base32 decoding; ASCII case-insensitive, padding optional, canonical trailing bits.
pub fn base32_decode(text: &str) -> Result<Vec<u8>> {
    let bad = |m: &str| e("invalid_input", m);
    let utf16_len = text.encode_utf16().count();
    let upper = text.to_ascii_uppercase();
    let s = upper.trim_end_matches('=');
    let s_len = s.encode_utf16().count();
    if utf16_len != s_len && utf16_len % 8 != 0 {
        return Err(bad("invalid base32 padding"));
    }
    if [1, 3, 6].contains(&(s_len % 8)) {
        return Err(bad("invalid base32 length"));
    }
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for ch in s.chars() {
        let v = B32
            .iter()
            .position(|&c| c as char == ch)
            .ok_or_else(|| bad("invalid base32 character"))? as u32;
        acc = ((acc << 5) | v) & 0xffff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 255) as u8);
        }
    }
    if acc & ((1 << bits) - 1) != 0 {
        return Err(bad("non-zero trailing bits"));
    }
    Ok(out)
}

/// HMAC algorithm of HOTP/TOTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpAlgorithm {
    Sha1,
    Sha256,
}

impl OtpAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            OtpAlgorithm::Sha1 => "SHA1",
            OtpAlgorithm::Sha256 => "SHA256",
        }
    }
}

/// Minimum OTP secret length in bytes (RFC 4226 section 4, 128 bits recommended, 80 required here).
pub const MIN_OTP_SECRET_BYTES: usize = 10;

fn otp_secret(s: &[u8]) -> Result<()> {
    if s.len() < MIN_OTP_SECRET_BYTES {
        return Err(e(
            "invalid_secret",
            "OTP secret must be at least 10 bytes (80 bits)",
        ));
    }
    Ok(())
}

fn check_digits(d: u32) -> Result<u32> {
    if (6..=8).contains(&d) {
        Ok(d)
    } else {
        Err(e("invalid_option", "digits must be 6, 7 or 8"))
    }
}

fn hotp_raw(key: &[u8], counter: u64, digits: u32, alg: OtpAlgorithm) -> String {
    let msg = counter.to_be_bytes();
    let mac: Vec<u8> = match alg {
        OtpAlgorithm::Sha1 => crypto::hmac_sha1(key, &msg).to_vec(),
        OtpAlgorithm::Sha256 => crypto::hmac_sha256(key, &msg).to_vec(),
    };
    let off = (mac[mac.len() - 1] & 15) as usize;
    let bin = ((mac[off] as u32 & 0x7f) << 24)
        | ((mac[off + 1] as u32) << 16)
        | ((mac[off + 2] as u32) << 8)
        | mac[off + 3] as u32;
    let code = bin % 10u32.pow(digits);
    format!("{:0width$}", code, width = digits as usize)
}

/// RFC 4226 HOTP.
pub fn hotp(secret: &[u8], counter: u64, digits: u32, alg: OtpAlgorithm) -> Result<String> {
    otp_secret(secret)?;
    let d = check_digits(digits)?;
    if counter as f64 > MAX_SAFE {
        return Err(e(
            "invalid_option",
            "counter must be an integer in 0..2^53-1",
        ));
    }
    Ok(hotp_raw(secret, counter, d, alg))
}

/// TOTP parameters (RFC 6238).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpOptions {
    pub period: u64,
    pub digits: u32,
    pub algorithm: OtpAlgorithm,
    pub t0: u64,
}

impl Default for TotpOptions {
    fn default() -> Self {
        TotpOptions {
            period: 30,
            digits: 6,
            algorithm: OtpAlgorithm::Sha1,
            t0: 0,
        }
    }
}

fn totp_step(time: u64, o: &TotpOptions) -> Result<u64> {
    if !(1..=86400).contains(&o.period) {
        return Err(e("invalid_option", "period must be an integer in 1..86400"));
    }
    if o.t0 as f64 > MAX_SAFE || time as f64 > MAX_SAFE {
        return Err(e("invalid_option", "time and t0 must be at most 2^53-1"));
    }
    if time < o.t0 {
        return Err(e("invalid_option", "time is before t0"));
    }
    Ok((time - o.t0) / o.period)
}

/// RFC 6238 TOTP for a time in seconds.
pub fn totp(secret: &[u8], time: u64, o: &TotpOptions) -> Result<String> {
    otp_secret(secret)?;
    let d = check_digits(o.digits)?;
    let step = totp_step(time, o)?;
    Ok(hotp_raw(secret, step, d, o.algorithm))
}

/// Matching step offset within `-window..=window` (window at most 10), or `None`.
pub fn verify_totp(
    secret: &[u8],
    code: &str,
    time: u64,
    o: &TotpOptions,
    window: u64,
) -> Result<Option<i64>> {
    otp_secret(secret)?;
    let d = check_digits(o.digits)?;
    let step = totp_step(time, o)?;
    if window > 10 {
        return Err(e("invalid_option", "window must be an integer in 0..10"));
    }
    if code.len() != d as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(None);
    }
    let mut found = None;
    let w = window as i64;
    for delta in -w..=w {
        let s = step as i64 + delta;
        if s < 0 {
            continue;
        }
        let c = hotp_raw(secret, s as u64, d, o.algorithm);
        if crypto::constant_time_eq(c.as_bytes(), code.as_bytes()) && found.is_none() {
            found = Some(delta);
        }
    }
    Ok(found)
}

fn pct_encode(s: &str) -> String {
    let mut out = String::new();
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// `otpauth://totp/...` URI for authenticator apps.
pub fn otpauth_uri(secret: &[u8], account: &str, issuer: &str, o: &TotpOptions) -> Result<String> {
    otp_secret(secret)?;
    let d = check_digits(o.digits)?;
    if !(1..=86400).contains(&o.period) {
        return Err(e("invalid_option", "period must be an integer in 1..86400"));
    }
    if account.is_empty() || account.contains(':') {
        return Err(e(
            "invalid_input",
            "account must be a non-empty string without ':'",
        ));
    }
    if issuer.is_empty() || issuer.contains(':') {
        return Err(e(
            "invalid_input",
            "issuer must be a non-empty string without ':'",
        ));
    }
    let secret32 = base32_encode(secret);
    Ok(format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
        pct_encode(issuer),
        pct_encode(account),
        secret32.trim_end_matches('='),
        pct_encode(issuer),
        o.algorithm.as_str(),
        d,
        o.period
    ))
}

// ---------------------------------------------------------------- RBAC

/// Maximum length of an inheritance chain.
pub const MAX_INHERITANCE: usize = 64;

fn is_role_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
}

fn check_pattern(p: &str, wildcard: bool) -> Result<()> {
    for s in p.split('.') {
        if s == "*" && wildcard {
            continue;
        }
        if s.is_empty()
            || !s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(e(
                "invalid_permission",
                "permission segments are [A-Za-z0-9_-]+ (or * in patterns)",
            ));
        }
    }
    Ok(())
}

fn matches(p: &str, perm: &str) -> bool {
    let a: Vec<&str> = p.split('.').collect();
    let b: Vec<&str> = perm.split('.').collect();
    for (i, s) in a.iter().enumerate() {
        if *s == "*" && i == a.len() - 1 {
            return b.len() >= a.len();
        }
        if i >= b.len() {
            return false;
        }
        if *s != "*" && *s != b[i] {
            return false;
        }
    }
    a.len() == b.len()
}

#[derive(Debug, Clone, Default)]
struct Role {
    allow: Vec<String>,
    deny: Vec<String>,
    inherits: Vec<String>,
}

/// A validated RBAC policy.
#[derive(Debug, Clone)]
pub struct Policy {
    roles: BTreeMap<String, Role>,
}

impl Policy {
    /// Parse and validate a policy document `{ "roles": { name: { permissions, inherits } } }`.
    pub fn from_value(policy: &Value) -> Result<Policy> {
        let bad = |m: &str| e("invalid_policy", m);
        let pm = policy
            .as_obj()
            .ok_or_else(|| bad("policy must be an object"))?;
        for (k, _) in pm {
            if k != "roles" {
                return Err(bad("unknown policy key"));
            }
        }
        let roles = match policy.get("roles") {
            Some(r @ Value::Obj(_)) => r,
            _ => return Err(bad("policy.roles must be an object")),
        };
        let mut out: BTreeMap<String, Role> = BTreeMap::new();
        let mut order: Vec<String> = Vec::new();
        for (name, r) in roles.js_entries() {
            if !is_role_name(name) {
                return Err(bad("invalid role name"));
            }
            let rm = r.as_obj().ok_or_else(|| bad("role must be an object"))?;
            for (k, _) in rm {
                if k != "permissions" && k != "inherits" {
                    return Err(bad("unknown role key"));
                }
            }
            let empty = Value::Arr(Vec::new());
            let perms = match r.get("permissions") {
                None | Some(Value::Null) => &empty,
                Some(v) => v,
            };
            let inh = match r.get("inherits") {
                None | Some(Value::Null) => &empty,
                Some(v) => v,
            };
            let (perms, inh) = match (perms.as_arr(), inh.as_arr()) {
                (Some(p), Some(i)) => (p, i),
                _ => return Err(bad("permissions and inherits must be arrays")),
            };
            let mut role = Role::default();
            for p in perms {
                let s = p
                    .as_str()
                    .ok_or_else(|| e("invalid_permission", "permission must be a string"))?;
                let (deny, pat) = match s.strip_prefix('!') {
                    Some(rest) => (true, rest),
                    None => (false, s),
                };
                check_pattern(pat, true)?;
                if deny {
                    role.deny.push(pat.to_string());
                } else {
                    role.allow.push(pat.to_string());
                }
            }
            for i in inh {
                match i.as_str() {
                    Some(s) if is_role_name(s) => role.inherits.push(s.to_string()),
                    _ => return Err(bad("inherits must list role names")),
                }
            }
            order.push(name.clone());
            out.insert(name.clone(), role);
        }
        for n in &order {
            for i in &out[n].inherits {
                if !out.contains_key(i) {
                    return Err(bad("unknown inherited role"));
                }
            }
        }
        let mut height: BTreeMap<String, usize> = BTreeMap::new();
        let mut on_path: BTreeSet<String> = BTreeSet::new();
        fn visit(
            n: &str,
            out: &BTreeMap<String, Role>,
            height: &mut BTreeMap<String, usize>,
            on_path: &mut BTreeSet<String>,
        ) -> Result<usize> {
            if let Some(h) = height.get(n) {
                return Ok(*h);
            }
            if on_path.contains(n) {
                return Err(e("invalid_policy", "inheritance cycle"));
            }
            if on_path.len() >= MAX_INHERITANCE {
                return Err(e("invalid_policy", "inheritance chain is longer than 64"));
            }
            on_path.insert(n.to_string());
            let mut h = 1;
            for i in &out[n].inherits {
                h = h.max(1 + visit(i, out, height, on_path)?);
            }
            on_path.remove(n);
            if h > MAX_INHERITANCE {
                return Err(e("invalid_policy", "inheritance chain is longer than 64"));
            }
            height.insert(n.to_string(), h);
            Ok(h)
        }
        for n in &order {
            visit(n, &out, &mut height, &mut on_path)?;
        }
        Ok(Policy { roles: out })
    }

    fn collect(&self, roles: &[&str]) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
        let mut stack: Vec<String> = Vec::new();
        for r in roles {
            if !self.roles.contains_key(*r) {
                return Err(e("invalid_role", "unknown role"));
            }
            stack.push(r.to_string());
        }
        let mut seen = BTreeSet::new();
        let (mut allow, mut deny) = (BTreeSet::new(), BTreeSet::new());
        while let Some(n) = stack.pop() {
            if !seen.insert(n.clone()) {
                continue;
            }
            let r = &self.roles[&n];
            allow.extend(r.allow.iter().cloned());
            deny.extend(r.deny.iter().cloned());
            stack.extend(r.inherits.iter().cloned());
        }
        Ok((allow, deny))
    }

    /// True when some role allows `permission` and none denies it (deny wins).
    pub fn can(&self, roles: &[&str], permission: &str) -> Result<bool> {
        let (allow, deny) = self.collect(roles)?;
        check_pattern(permission, false)?;
        if deny.iter().any(|d| matches(d, permission)) {
            return Ok(false);
        }
        Ok(allow.iter().any(|a| matches(a, permission)))
    }

    /// Effective allow and deny patterns, sorted and without duplicates.
    pub fn effective_permissions(&self, roles: &[&str]) -> Result<(Vec<String>, Vec<String>)> {
        let (allow, deny) = self.collect(roles)?;
        Ok((allow.into_iter().collect(), deny.into_iter().collect()))
    }
}

// ---------------------------------------------------------------- contract entry point

/// `{"hex": "..."}` to bytes (bad hex: `invalid_input`); any other value is returned as is.
fn hex_arg(v: Option<&Value>) -> Result<Option<Vec<u8>>> {
    if let Some(o @ Value::Obj(m)) = v {
        if m.len() == 1 {
            if let Some(Value::Str(h)) = o.get("hex") {
                return crypto::from_hex(h)
                    .map(Some)
                    .ok_or_else(|| e("invalid_input", "invalid hex"));
            }
        }
    }
    Ok(None)
}

fn bytes_arg(v: Option<&Value>, code: &'static str) -> Result<Vec<u8>> {
    if let Some(b) = hex_arg(v)? {
        return Ok(b);
    }
    match v {
        Some(Value::Str(s)) => Ok(s.as_bytes().to_vec()),
        _ => Err(e(code, "expected a string or bytes")),
    }
}

fn otp_opts(v: Option<&Value>, keys: &[&str]) -> Result<(TotpOptions, Value)> {
    let o = check_keys(v, keys)?;
    let mut t = TotpOptions::default();
    if let Some(d) = o.get("digits") {
        t.digits = match safe_uint(d) {
            Some(n) if (6..=8).contains(&n) => n as u32,
            _ => return Err(e("invalid_option", "digits must be 6, 7 or 8")),
        };
    }
    if let Some(a) = o.get("algorithm") {
        t.algorithm = match a.as_str() {
            Some("SHA1") => OtpAlgorithm::Sha1,
            Some("SHA256") => OtpAlgorithm::Sha256,
            _ => return Err(e("invalid_option", "algorithm must be SHA1 or SHA256")),
        };
    }
    Ok((t, o))
}

fn period_t0(t: &mut TotpOptions, o: &Value, with_t0: bool) -> Result<()> {
    if let Some(p) = o.get("period") {
        t.period = match safe_uint(p) {
            Some(n) if (1..=86400).contains(&n) => n,
            _ => return Err(e("invalid_option", "period must be an integer in 1..86400")),
        };
    }
    if with_t0 {
        if let Some(z) = o.get("t0") {
            t.t0 = safe_uint(z)
                .ok_or_else(|| e("invalid_option", "t0 must be a non-negative integer"))?;
        }
    }
    Ok(())
}

fn time_arg(v: Option<&Value>) -> Result<u64> {
    v.and_then(safe_uint).ok_or_else(|| {
        e(
            "invalid_option",
            "time must be a non-negative integer number of seconds",
        )
    })
}

fn str_arg<'a>(v: Option<&'a Value>, code: &'static str, m: &str) -> Result<&'a str> {
    v.and_then(|x| x.as_str()).ok_or_else(|| e(code, m))
}

fn roles_arg(v: Option<&Value>) -> Result<Vec<&str>> {
    let a = v
        .and_then(|x| x.as_arr())
        .ok_or_else(|| e("invalid_role", "roles must be an array"))?;
    a.iter()
        .map(|x| x.as_str().ok_or_else(|| e("invalid_role", "unknown role")))
        .collect()
}

fn pair(h: Value, c: Value) -> Value {
    let mut o = Value::Obj(Vec::new());
    o.set("header", h);
    o.set("claims", c);
    o
}

fn hex_value(b: &[u8]) -> Value {
    let mut o = Value::Obj(Vec::new());
    o.set("hex", Value::Str(crypto::to_hex(b)));
    o
}

/// Dynamic entry point with the contract's JSON calling convention; `{"hex": "..."}` denotes bytes.
pub fn call(func: &str, args: &[Value]) -> Result<Value> {
    let a = |i: usize| args.get(i);
    let s = |x: String| Value::Str(x);
    match func {
        "signJwt" => {
            let secret = bytes_arg(a(1), "invalid_secret")?;
            jwt_secret(&secret)?;
            let o = check_keys(a(2), &["kid"])?;
            let claims = a(0).cloned().unwrap_or(Value::Null);
            if claims.as_obj().is_none() || !finite_tree(&claims) {
                return Err(e("invalid_claim", "claims must be a JSON object"));
            }
            let kid = match o.get("kid") {
                None => None,
                Some(Value::Str(k)) if !k.is_empty() => Some(k.clone()),
                Some(_) => return Err(e("invalid_option", "kid must be a non-empty string")),
            };
            sign_jwt(&claims, &secret, kid.as_deref()).map(s)
        }
        "verifyJwt" => {
            let secret = bytes_arg(a(1), "invalid_secret")?;
            jwt_secret(&secret)?;
            let o = check_keys(a(2), &["now", "leeway", "issuer", "audience", "requireExp"])?;
            let now = o
                .get("now")
                .and_then(|v| v.as_f64())
                .ok_or_else(|| e("invalid_option", "now must be a finite number of seconds"))?;
            let mut vo = VerifyOptions::at(now);
            if let Some(l) = o.get("leeway") {
                vo.leeway = match l.as_f64() {
                    Some(x) if x >= 0.0 => x,
                    _ => return Err(e("invalid_option", "leeway must be a non-negative number")),
                };
            }
            if let Some(i) = o.get("issuer") {
                vo.issuer = Some(
                    str_arg(Some(i), "invalid_option", "issuer must be a string")?.to_string(),
                );
            }
            if let Some(i) = o.get("audience") {
                vo.audience = Some(
                    str_arg(Some(i), "invalid_option", "audience must be a string")?.to_string(),
                );
            }
            if let Some(r) = o.get("requireExp") {
                vo.require_exp = r
                    .as_bool()
                    .ok_or_else(|| e("invalid_option", "requireExp must be a boolean"))?;
            }
            let token = str_arg(a(0), "invalid_token", "token must be a string")?;
            let (h, c) = verify_jwt(token, &secret, &vo)?;
            Ok(pair(h, c))
        }
        "decodeJwtUnverified" => {
            let token = str_arg(a(0), "invalid_token", "token must be a string")?;
            let (h, c) = decode_jwt_unverified(token)?;
            Ok(pair(h, c))
        }
        "hashPassword" => {
            let salt_hex = hex_arg(a(1))?;
            let pw = str_arg(a(0), "invalid_input", "password must be a string")?;
            let salt = match salt_hex {
                Some(b) => b,
                None => match a(1) {
                    Some(Value::Str(h)) => crypto::from_hex(h)
                        .ok_or_else(|| e("invalid_salt", "salt must be bytes or hex"))?,
                    _ => return Err(e("invalid_salt", "salt must be bytes or hex")),
                },
            };
            if salt.len() < MIN_SALT_BYTES {
                return Err(e("invalid_salt", "salt must be at least 16 bytes"));
            }
            let n = match a(2) {
                None => DEFAULT_ITERATIONS,
                Some(v) => match safe_uint(v) {
                    Some(n) if n <= u32::MAX as u64 => check_iterations(n as u32)?,
                    _ => {
                        return Err(e(
                            "invalid_option",
                            "iterations must be an integer in 1000..10000000",
                        ))
                    }
                },
            };
            hash_password(pw, &salt, n).map(s)
        }
        "verifyPassword" => {
            let phc = str_arg(a(1), "invalid_hash", "hash must be a string")?;
            let p = parse_phc(phc)?;
            let pw = str_arg(a(0), "invalid_input", "password must be a string")?;
            let h = crypto::pbkdf2_sha256(pw.as_bytes(), &p.salt, p.n, 32);
            Ok(Value::Bool(crypto::constant_time_eq(&h, &p.hash)))
        }
        "needsRehash" => {
            let n = match a(1) {
                None => DEFAULT_ITERATIONS,
                Some(v) => match safe_uint(v) {
                    Some(n) if n <= u32::MAX as u64 => check_iterations(n as u32)?,
                    _ => {
                        return Err(e(
                            "invalid_option",
                            "iterations must be an integer in 1000..10000000",
                        ))
                    }
                },
            };
            let phc = str_arg(a(0), "invalid_hash", "hash must be a string")?;
            needs_rehash(phc, n).map(Value::Bool)
        }
        "base32Encode" => Ok(s(base32_encode(&bytes_arg(a(0), "invalid_input")?))),
        "base32Decode" => {
            let t = str_arg(a(0), "invalid_input", "text must be a string")?;
            Ok(hex_value(&base32_decode(t)?))
        }
        "hotp" => {
            let key = bytes_arg(a(0), "invalid_secret")?;
            otp_secret(&key)?;
            let (t, _) = otp_opts(a(2), &["digits", "algorithm"])?;
            let c = a(1)
                .and_then(safe_uint)
                .ok_or_else(|| e("invalid_option", "counter must be an integer in 0..2^53-1"))?;
            hotp(&key, c, t.digits, t.algorithm).map(s)
        }
        "totp" => {
            let key = bytes_arg(a(0), "invalid_secret")?;
            otp_secret(&key)?;
            let (mut t, o) = otp_opts(a(2), &["period", "digits", "algorithm", "t0"])?;
            period_t0(&mut t, &o, true)?;
            let time = time_arg(a(1))?;
            totp(&key, time, &t).map(s)
        }
        "verifyTotp" => {
            let key = bytes_arg(a(0), "invalid_secret")?;
            otp_secret(&key)?;
            let (mut t, o) = otp_opts(a(3), &["period", "digits", "algorithm", "t0", "window"])?;
            period_t0(&mut t, &o, true)?;
            let time = time_arg(a(2))?;
            totp_step(time, &t)?;
            let window = match o.get("window") {
                None => 1,
                Some(w) => match safe_uint(w) {
                    Some(n) if n <= 10 => n,
                    _ => return Err(e("invalid_option", "window must be an integer in 0..10")),
                },
            };
            let code = match a(1) {
                Some(Value::Str(c)) => c.as_str(),
                _ => return Ok(Value::Null),
            };
            Ok(match verify_totp(&key, code, time, &t, window)? {
                Some(d) => Value::Num(d as f64),
                None => Value::Null,
            })
        }
        "otpauthUri" => {
            let key = bytes_arg(a(0), "invalid_secret")?;
            otp_secret(&key)?;
            let (mut t, o) = otp_opts(a(3), &["period", "digits", "algorithm"])?;
            period_t0(&mut t, &o, false)?;
            let account = str_arg(
                a(1),
                "invalid_input",
                "account must be a non-empty string without ':'",
            )?;
            let issuer = str_arg(
                a(2),
                "invalid_input",
                "issuer must be a non-empty string without ':'",
            )?;
            otpauth_uri(&key, account, issuer, &t).map(s)
        }
        "validatePolicy" => {
            Policy::from_value(a(0).unwrap_or(&Value::Null)).map(|_| Value::Bool(true))
        }
        "can" => {
            let p = Policy::from_value(a(0).unwrap_or(&Value::Null))?;
            let roles = roles_arg(a(1))?;
            p.collect(&roles)?;
            let perm = str_arg(a(2), "invalid_permission", "permission must be a string")?;
            p.can(&roles, perm).map(Value::Bool)
        }
        "effectivePermissions" => {
            let p = Policy::from_value(a(0).unwrap_or(&Value::Null))?;
            let roles = roles_arg(a(1))?;
            let (allow, deny) = p.effective_permissions(&roles)?;
            let list = |v: Vec<String>| Value::Arr(v.into_iter().map(Value::Str).collect());
            let mut o = Value::Obj(Vec::new());
            o.set("allow", list(allow));
            o.set("deny", list(deny));
            Ok(o)
        }
        _ => Err(e("invalid_option", "unknown function")),
    }
}
