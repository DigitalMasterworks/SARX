//! §5.1.0 Overview — SARX v1 — Cantor-Immune Stream Cipher Verdult-7 Harness (Rust port)
//! - AEAD malleability, KPA heads, seek equivalence, distinguishing,
//!   bit-position bias, weak-key scan, key sensitivity, tag forgery, header invariants
//! Output: sarx_v7.log (configurable via -log)

/* =============================================================================
 * SARX — sarx_v7.rs — Program v5.0.0
 * Numbering: Sections §5.X.0, Subsections §5.X.Y (code-only labels)
 * =============================================================================
 */

// ============================================================================
// §5.2.0 Imports
// ============================================================================
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};

use blake3::Hasher as Blake3;
use anyhow::{Context, Result};

use sarx::{
    sarx::{generate_config_with_timestamp, generate_stream, SARXConfig},
    VAULT_VERSION,
};

/// ===========================================================================
/// §5.3.0 Params & CLI
/// ===========================================================================

/* §5.3.1 Params struct */
#[derive(Clone)]
struct Params {
    n_keys: i32,
    n_ivs: i32,
    bytes_per_stream: usize,
    seed: u64,
    log_path: String,
}

/* §5.3.2 parse_args: CLI → Params */
fn parse_args() -> Params {
    let mut p = Params {
        n_keys: 10,
        n_ivs: 64,
        bytes_per_stream: 1usize << 20,
        seed: 0xC0DEFACE12345678u64,
        log_path: "sarx_v7.log".to_string(),
    };
    let it = env::args().skip(1).collect::<Vec<_>>();
    let mut i = 0usize;
    while i < it.len() {
        match it[i].as_str() {
            "-keys" if i + 1 < it.len() => {
                p.n_keys = it[i + 1].parse().unwrap_or(p.n_keys);
                i += 2;
            }
            "-ivs" if i + 1 < it.len() => {
                p.n_ivs = it[i + 1].parse().unwrap_or(p.n_ivs);
                i += 2;
            }
            "-bytes" if i + 1 < it.len() => {
                p.bytes_per_stream = it[i + 1].parse().unwrap_or(p.bytes_per_stream);
                i += 2;
            }
            "-seed" if i + 1 < it.len() => {
                // hex like C version
                let s = it[i + 1].trim_start_matches("0x");
                p.seed = u64::from_str_radix(s, 16).unwrap_or(p.seed);
                i += 2;
            }
            "-log" if i + 1 < it.len() => {
                p.log_path = it[i + 1].clone();
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }
    p
}

/// ===========================================================================
/// §5.4.0 RNG (deterministic splitmix64; single-threaded-safe here)
/// ===========================================================================

/* §5.4.1 splitmix64 core */
#[inline]
fn splitmix64(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9E37_79B9_7F4A_7C15u64);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9u64);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EBu64);
    z ^ (z >> 31)
}

/* §5.4.2 G_SEED + rng_seed */
static mut G_SEED: u64 = 1;
fn rng_seed(s: u64) { unsafe { G_SEED = if s == 0 { 1 } else { s }; } }

/* §5.4.3 rng_u64 */
#[allow(static_mut_refs)]
fn rng_u64() -> u64 {
    // Single-threaded harness; safe in this context.
    unsafe { splitmix64(&mut G_SEED) }
}

/* §5.4.4 rng_u32 */
fn rng_u32() -> u32 { (rng_u64() >> 32) as u32 }

/// ===========================================================================
/// §5.5.0 Small Utils
/// ===========================================================================

/* §5.5.1 round_up_32 */
#[inline]
fn round_up_32(x: usize) -> usize { (x + 31) & !31 }

/* §5.5.2 hamming_bits(a,b) */
fn hamming_bits(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones() as usize).sum()
}

/* §5.5.3 serial_corr(buf) */
fn serial_corr(buf: &[u8]) -> f64 {
    let n = buf.len();
    if n < 3 { return 0.0; }
    let mut sx = 0.0f64;
    let mut sxx = 0.0f64;
    let mut sxy = 0.0f64;
    for i in 0..(n - 1) {
        let x = buf[i] as f64;
        let y = buf[i + 1] as f64;
        sx += x;
        sxx += x * x;
        sxy += x * y;
    }
    let n1 = (n - 1) as f64;
    let num = n1 * sxy - sx * sx;
    let den = ((n1 * sxx - sx * sx) * (n1 * sxx - sx * sx)).sqrt();
    if den == 0.0 { 0.0 } else { num / den }
}

/* §5.5.4 chi2_bytes(buf) */
fn chi2_bytes(buf: &[u8]) -> f64 {
    let mut f = [0u32; 256];
    for &b in buf { f[b as usize] += 1; }
    let exp = buf.len() as f64 / 256.0;
    let mut chi2 = 0.0;
    for &cnt in &f {
        let d = cnt as f64 - exp;
        chi2 += (d * d) / exp;
    }
    chi2
}

/* §5.5.5 ctcmp32: constant-time-ish compare → {0,≠0} */
#[inline] fn ctcmp32(a: &[u8; 32], b: &[u8; 32]) -> i32 {
    let mut d: u32 = 0;
    for i in 0..32 { d |= (a[i] ^ b[i]) as u32; }
    d as i32
}

/* §5.5.6 be32 */
#[inline]
fn be32(x: u32) -> [u8; 4] {
    [(x >> 24) as u8, (x >> 16) as u8, (x >> 8) as u8, x as u8]
}
/* §5.5.7 be64 */
#[inline]
fn be64(x: u64) -> [u8; 8] { x.to_be_bytes() }
/* §5.5.8 le64 */
#[inline]
fn le64(x: u64) -> [u8; 8] { x.to_le_bytes() }

/// ===========================================================================
/// §5.6.0 Deterministic ts/nonce derivation (harness-compat with C)
/// ===========================================================================

/* §5.6.1 derive_ts_nonce(seed,key_idx,iv_idx) -> (ts_ns, nonce12) */
/// Matches C: input "HARNESS-TSNONCE" (15 bytes) + 1 zero delimiter (total 16),
/// then seed (be64), key_idx (be32), iv_idx (be32)
/// output: nonce = first 12 bytes; ts = big-endian out[12..20] (if zero → set to 1)
fn derive_ts_nonce(seed: u64, key_idx: i32, iv_idx: i32) -> (u64, [u8; 12]) {
    let mut input = [0u8; 16 + 8 + 4 + 4];
    input[..15].copy_from_slice(b"HARNESS-TSNONCE");
    input[16..24].copy_from_slice(&be64(seed));
    input[24..28].copy_from_slice(&be32(key_idx as u32));
    input[28..32].copy_from_slice(&be32(iv_idx as u32));

    let mut out = [0u8; 32];
    let mut h = Blake3::new();
    h.update(&input);
    h.finalize_xof().fill(&mut out);

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&out[..12]);

    let mut t: u64 = 0;
    for i in 12..20 { t = (t << 8) | (out[i] as u64); }
    if t == 0 { t = 1; }

    (t, nonce)
}

/// ===========================================================================
/// §5.7.0 Passwords & Configs
/// ===========================================================================

/* §5.7.1 KeySlot */
#[derive(Clone)]
struct KeySlot {
    _cfg: SARXConfig,
    password: String,
}

/* §5.7.2 make_password(cps) — ASCII 33..126 from rng_u32 */
fn make_password(cps: usize) -> String {
    // C version made printable ASCII 33..126; do the same deterministically from rng_u32
    let cps = cps.clamp(30, 200);
    let mut s = String::with_capacity(cps);
    for _ in 0..cps {
        let c = 33u8 + (rng_u32() % 94) as u8;
        s.push(c as char);
    }
    s
}

/* §5.7.3 setup_keys(n_keys) */
fn setup_keys(n_keys: i32) -> Vec<KeySlot> {
    let n = n_keys.max(0) as usize;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        let pw = make_password(64);
        // match C: arbitrary ts for initial cfg (not used by scheme later)
        let cfg = generate_config_with_timestamp(&pw, None, 0, 123_456_789u64)
            .expect("generate_config_with_timestamp");
        v.push(KeySlot { _cfg: cfg, password: pw });
    }
    v
}

/* §5.7.4 salt_from_ts_nonce(ts,nonce12) */
fn salt_from_ts_nonce(ts_ns: u64, nonce12: &[u8; 12]) -> [u8; 32] {
    let mut inbuf = [0u8; 8 + 12];
    inbuf[..8].copy_from_slice(&be64(ts_ns));
    inbuf[8..20].copy_from_slice(nonce12);
    let mut out = [0u8; 32];
    let mut h = Blake3::new();
    h.update(&inbuf);
    h.finalize_xof().fill(&mut out);
    out
}

/* §5.7.5 derive_okm_from_pw(pw,salt32) -> (k_stream, ks_len, k_mac32) */
fn derive_okm_from_pw(
    pw: &str,
    salt32: &[u8; 32],
) -> (Vec<u8>, usize, [u8; 32]) {
    use argon2::{Algorithm, Argon2, Params, Version};

    let pass_bytes = pw.as_bytes().len();
    let ks_len = round_up_32(pass_bytes).max(32);
    let okm_len = ks_len + 32;
    let mut okm = vec![0u8; okm_len.max(1)];

    let params = Params::new(1 << 17, 3, 1, Some(okm_len)).unwrap(); // 128 MiB, t=3, lanes=1
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    a2.hash_password_into(pw.as_bytes(), salt32, &mut okm)
        .expect("argon2id hash raw");

    let k_stream = okm[..ks_len].to_vec();
    let mut k_mac = [0u8; 32];
    k_mac.copy_from_slice(&okm[ks_len..ks_len + 32]);
    (k_stream, ks_len, k_mac)
}

/* §5.7.6 build_postmix(k_stream,ks_len,nonce,ts) */
fn build_postmix(k_stream: &[u8], ks_len: usize, nonce: &[u8; 12], ts_ns: u64) -> Vec<u8> {
    // "SARX2DU-POST\0\0\0\0" (16) || k_stream || nonce(12) || ts_be(8)
    let mut pm = Vec::with_capacity(16 + ks_len + 12 + 8);
    pm.extend_from_slice(b"SARX2DU-POST\0\0\0\0");
    pm.extend_from_slice(k_stream);
    pm.extend_from_slice(nonce);
    pm.extend_from_slice(&be64(ts_ns));
    pm
}

/* §5.7.7 build_header61(...) -> [u8;61] */
fn build_header61(
    ts_ns: u64,
    nonce12: &[u8; 12],
    salt32: &[u8; 32],
    t_cost: u8,
    m_cost: u8,
    lanes: u8,
    kdf_id: u8,
) -> [u8; 61] {
    let mut h = [0u8; 61];
    h[0..4].copy_from_slice(b"SARX");
    h[4] = VAULT_VERSION;
    h[5..37].copy_from_slice(salt32);
    h[37..45].copy_from_slice(&be64(ts_ns));
    h[45..57].copy_from_slice(nonce12);
    h[57] = t_cost;
    h[58] = m_cost;
    h[59] = lanes;
    h[60] = kdf_id;
    h
}

/// ===========================================================================
/// §5.8.0 Scheme Operations (Vault encrypt/decrypt in-memory)
/// ===========================================================================

/* §5.8.1 scheme_encrypt_vault(key,pt,ts,nonce) -> vault bytes */
/// produce vault blob in memory: header(61) || tag(32) || ciphertext
fn scheme_encrypt_vault(
    key: &KeySlot,
    plaintext: &[u8],
    ts_ns: u64,
    nonce12: &[u8; 12],
) -> Vec<u8> {
    let salt32 = salt_from_ts_nonce(ts_ns, nonce12);

    // derive okm → k_stream, k_mac
    let (k_stream, ks_len, k_mac) = derive_okm_from_pw(&key.password, &salt32);

    // config from RAW password w/ timestamp
    let cfg = generate_config_with_timestamp(&key.password, None, 0, ts_ns)
        .expect("generate_config_with_timestamp");

    // postmix
    let pm = build_postmix(&k_stream, ks_len, nonce12, ts_ns);

    // keystream + XOR
    let plen = plaintext.len();
    let mut ks = vec![0u8; plen.max(1)];
    generate_stream(&cfg, Some(&pm), 0, plen, &mut ks).expect("generate_stream");
    let mut ct = vec![0u8; plen];
    for i in 0..plen { ct[i] = plaintext[i] ^ ks[i]; }

    // header (Argon2 params fixed)
    let header = build_header61(ts_ns, nonce12, &salt32, 3, 17, 1, 2);

    // MAC over "SARX2DU-MAC-v1" || header || len_le || ciphertext
    let mut mac = Blake3::new_keyed(&k_mac);
    mac.update(b"SARX2DU-MAC-v1");
    mac.update(&header);
    mac.update(&le64(plen as u64));
    mac.update(&ct);
    let mut tag = [0u8; 32];
    mac.finalize_xof().fill(&mut tag);

    // assemble
    let mut vault = Vec::with_capacity(61 + 32 + plen);
    vault.extend_from_slice(&header);
    vault.extend_from_slice(&tag);
    vault.extend_from_slice(&ct);

    // hygiene: test harness keeps buffers; no explicit zeroize required here
    vault
}

/* §5.8.2 scheme_decrypt_vault(key,vault) -> Result<pt,code> */
/// returns: Ok(plaintext) or Err(code) with code = -1 parse, -2 tag fail
fn scheme_decrypt_vault(
    key: &KeySlot,
    vault: &[u8],
) -> std::result::Result<Vec<u8>, i32> {
    if vault.len() < 93 { return Err(-1); }
    if &vault[0..4] != b"SARX" { return Err(-1); }
    if vault[4] != VAULT_VERSION { return Err(-1); }

    let mut salt32 = [0u8; 32];
    salt32.copy_from_slice(&vault[5..37]);

    let mut ts_be = [0u8; 8];
    ts_be.copy_from_slice(&vault[37..45]);
    let ts_ns = u64::from_be_bytes(ts_be);

    let mut nonce12 = [0u8; 12];
    nonce12.copy_from_slice(&vault[45..57]);

    let tag_file_slice = &vault[61..93];
    let mut tag_file = [0u8; 32];
    tag_file.copy_from_slice(tag_file_slice);

    let ct = &vault[93..];

    // derive okm again
    let (k_stream, ks_len, k_mac) = derive_okm_from_pw(&key.password, &salt32);

    // recompute MAC
    let mut mac = Blake3::new_keyed(&k_mac);
    mac.update(b"SARX2DU-MAC-v1");
    mac.update(&vault[..61]); // full header
    mac.update(&le64(ct.len() as u64));
    mac.update(ct);
    let mut tag_calc = [0u8; 32];
    mac.finalize_xof().fill(&mut tag_calc);

    if ctcmp32(&tag_calc, &tag_file) != 0 { return Err(-2); }

    // decrypt
    let cfg = generate_config_with_timestamp(&key.password, None, 0, ts_ns)
        .expect("generate_config_with_timestamp");
    let pm = build_postmix(&k_stream, ks_len, &nonce12, ts_ns);

    let mut ks = vec![0u8; ct.len().max(1)];
    generate_stream(&cfg, Some(&pm), 0, ct.len(), &mut ks).expect("generate_stream");

    let mut pt = vec![0u8; ct.len()];
    for i in 0..ct.len() { pt[i] = ct[i] ^ ks[i]; }

    Ok(pt)
}

/// ===========================================================================
/// §5.9.0 Tests (Verdult-7 battery)
/// ===========================================================================

/* §5.9.1 test1_aead */
fn test1_aead(log: &mut BufWriter<File>, p: &Params, keys: &[KeySlot]) -> Result<()> {
    writeln!(log, "[Test 1: AEAD malleability (auth detection)]")?;
    let n = p.bytes_per_stream;
    let mut pt = vec![0u8; n];
    for (i, b) in pt.iter_mut().enumerate() { *b = i as u8; }

    for (k_idx, key) in keys.iter().enumerate() {
        let (ts, nonce) = derive_ts_nonce(p.seed, k_idx as i32, 0);
        let mut vault = scheme_encrypt_vault(key, &pt, ts, &nonce);
        // flip random bit in ciphertext
        let ct_off = 93usize;
        let vlen = vault.len();
        let bitpos = (rng_u64() % (((vlen - ct_off) as u64) * 8)).max(0) as usize;
        let byte_idx = ct_off + (bitpos >> 3);
        let bitmask = 1u8 << (bitpos & 7);
        vault[byte_idx] ^= bitmask;

        let rc = match scheme_decrypt_vault(key, &vault) {
            Ok(_) => 0,
            Err(code) => code,
        };
        writeln!(log, "Key{} IV0 ct_bitflip_auth_detected={}", k_idx, if rc == -2 { 1 } else { 0 })?;

        // undo & flip header bit (salt)
        vault[byte_idx] ^= bitmask;
        let salt_byte = 5 + (rng_u32() as usize % 32);
        vault[salt_byte] ^= 0x01;
        let rc = match scheme_decrypt_vault(key, &vault) {
            Ok(_) => 0,
            Err(code) => code,
        };
        writeln!(log, "Key{} IV0 header_bitflip_auth_detected={}", k_idx, if rc == -2 { 1 } else { 0 })?;
    }
    Ok(())
}

/* §5.9.2 test2_kpa_heads */
fn test2_kpa_heads(log: &mut BufWriter<File>, p: &Params, keys: &[KeySlot]) -> Result<()> {
    writeln!(log, "[Test 2: Known-plaintext recovery]")?;
    let pt = [0u8, 1, 2, 3];

    for (k_idx, key) in keys.iter().enumerate() {
        for iv in 0..p.n_ivs {
            let (ts, nonce) = derive_ts_nonce(p.seed, k_idx as i32, iv);
            let vault = scheme_encrypt_vault(key, &pt, ts, &nonce);

            // derive keystream head by XOR CT with PT (first 4 bytes)
            let head = ((pt[0] ^ vault[93 + 0]) as u32) << 24
                | ((pt[1] ^ vault[93 + 1]) as u32) << 16
                | ((pt[2] ^ vault[93 + 2]) as u32) << 8
                | ((pt[3] ^ vault[93 + 3]) as u32);
            writeln!(log, "K{} IV{} KS_head=0x{:08X}", k_idx, iv, head)?;
        }
    }
    Ok(())
}

/* §5.9.3 test3_seek_equivalence */
fn test3_seek_equivalence(log: &mut BufWriter<File>, p: &Params, keys: &[KeySlot]) -> Result<()> {
    writeln!(log, "[Test 3: Seek-equivalence]")?;
    let n = p.bytes_per_stream;
    let mut pt = vec![0u8; n];
    for (i, b) in pt.iter_mut().enumerate() { *b = (i as u8).wrapping_mul(3); }

    let kcap = p.n_keys.min(6) as usize;
    let ivcap = p.n_ivs.min(6) as usize;

    for k in 0..kcap {
        let key = &keys[k];
        for iv in 0..ivcap {
            let (ts, nonce) = derive_ts_nonce(p.seed, k as i32, iv as i32);
            let salt32 = salt_from_ts_nonce(ts, &nonce);
            let (k_stream, ks_len, _k_mac) = derive_okm_from_pw(&key.password, &salt32);
            let cfg = generate_config_with_timestamp(&key.password, None, 0, ts)?;
            let pm = build_postmix(&k_stream, ks_len, &nonce, ts);

            let mut whole = vec![0u8; n];
            generate_stream(&cfg, Some(&pm), 0, n, &mut whole)?;

            let mut piec = vec![0u8; n];
            let a = 1 + (rng_u64() as usize % n.max(3) / 3).max(1);
            let mut b = a + 1 + (rng_u64() as usize % n.max(3) / 3).max(1);
            if b >= n { b = n - 1; }

            generate_stream(&cfg, Some(&pm), 0, a, &mut piec[..a])?;
            generate_stream(&cfg, Some(&pm), a as u64, b - a, &mut piec[a..b])?;
            generate_stream(&cfg, Some(&pm), b as u64, n - b, &mut piec[b..])?;

            let mism = whole.iter().zip(&piec).filter(|(x, y)| x != y).count();
            writeln!(log, "K{} IV{} seek_mismatch_bytes={}", k, iv, mism)?;
        }
    }
    Ok(())
}

/* §5.9.4 test4_distinguishing */
fn test4_distinguishing(log: &mut BufWriter<File>, p: &Params, keys: &[KeySlot]) -> Result<()> {
    writeln!(log, "[Test 4: Distinguishing (chi2 & serial corr)]")?;
    let n = p.bytes_per_stream;

    let kcap = p.n_keys.min(6) as usize;
    let ivcap = p.n_ivs.min(8) as usize;
    let mut buf = vec![0u8; n];

    let mut chi_min = f64::MAX;
    let mut chi_max: f64 = 0.0;
    let mut chi_sum = 0.0;
    let mut sc_min = f64::MAX;
    let mut sc_max = f64::MIN;
    let mut sc_sum = 0.0;
    let mut count = 0;

    for k in 0..kcap {
        let key = &keys[k];
        for iv in 0..ivcap {
            let (ts, nonce) = derive_ts_nonce(p.seed, k as i32, iv as i32);
            let salt32 = salt_from_ts_nonce(ts, &nonce);
            let (k_stream, ks_len, _k_mac) = derive_okm_from_pw(&key.password, &salt32);
            let cfg = generate_config_with_timestamp(&key.password, None, 0, ts)?;
            let pm = build_postmix(&k_stream, ks_len, &nonce, ts);

            generate_stream(&cfg, Some(&pm), 0, n, &mut buf)?;

            let c2 = chi2_bytes(&buf);
            let sc = serial_corr(&buf);
            chi_min = chi_min.min(c2);
            chi_max = chi_max.max(c2);
            chi_sum += c2;

            sc_min = sc_min.min(sc);
            sc_max = sc_max.max(sc);
            sc_sum += sc;

            count += 1;
        }
    }

    writeln!(
        log,
        "keystream chi2(df=255) min={:.2} max={:.2} avg={:.2}",
        chi_min,
        chi_max,
        chi_sum / (count as f64)
    )?;
    writeln!(
        log,
        "keystream serial_corr min={:.4} max={:.4} avg={:.4}",
        sc_min,
        sc_max,
        sc_sum / (count as f64)
    )?;
    Ok(())
}

/* §5.9.5 test5_bit_bias */
fn test5_bit_bias(log: &mut BufWriter<File>, p: &Params, keys: &[KeySlot]) -> Result<()> {
    writeln!(log, "[Test 5: Bit-position bias across IVs]")?;
    const W: usize = 4096;
    let mut ones = vec![0u32; W * 8];
    let mut buf = vec![0u8; W];

    for (k_idx, key) in keys.iter().enumerate().take(p.n_keys as usize) {
        ones.fill(0);
        for iv in 0..p.n_ivs {
            let (ts, nonce) = derive_ts_nonce(p.seed, k_idx as i32, iv);
            let salt32 = salt_from_ts_nonce(ts, &nonce);
            let (k_stream, ks_len, _k_mac) = derive_okm_from_pw(&key.password, &salt32);
            let cfg = generate_config_with_timestamp(&key.password, None, 0, ts)?;
            let pm = build_postmix(&k_stream, ks_len, &nonce, ts);

            generate_stream(&cfg, Some(&pm), 0, W, &mut buf)?;

            for (i, &b) in buf.iter().enumerate() {
                for bit in 0..8 {
                    if (b & (1u8 << bit)) != 0 { ones[i * 8 + bit] += 1; }
                }
            }
        }
        let mut worst = 0.0f64;
        let mut avg = 0.0f64;
        for i in 0..W * 8 {
            let p1 = ones[i] as f64 / p.n_ivs as f64;
            let dev = (p1 - 0.5).abs();
            worst = worst.max(dev);
            avg += dev;
        }
        avg /= (W * 8) as f64;
        writeln!(log, "Key{} bias: worst={:.4} avg={:.4}", k_idx, worst, avg)?;
    }
    Ok(())
}

/* §5.9.6 test6_weak_keys */
fn test6_weak_keys(log: &mut BufWriter<File>, p: &Params, keys: &[KeySlot]) -> Result<()> {
    writeln!(log, "[Test 6: Weak-key scan (IV head collisions)]")?;
    for (k_idx, key) in keys.iter().enumerate() {
        let mut heads = vec![0u32; p.n_ivs as usize];
        for iv in 0..p.n_ivs {
            let (ts, nonce) = derive_ts_nonce(p.seed, k_idx as i32, iv);
            let salt32 = salt_from_ts_nonce(ts, &nonce);
            let (k_stream, ks_len, _k_mac) = derive_okm_from_pw(&key.password, &salt32);
            let cfg = generate_config_with_timestamp(&key.password, None, 0, ts)?;
            let pm = build_postmix(&k_stream, ks_len, &nonce, ts);
            let mut b = [0u8; 4];
            generate_stream(&cfg, Some(&pm), 0, 4, &mut b)?;
            heads[iv as usize] =
                ((b[0] as u32) << 24) | ((b[1] as u32) << 16) | ((b[2] as u32) << 8) | b[3] as u32;
        }
        let mut dups = 0;
        for i in 0..p.n_ivs as usize {
            for j in (i + 1)..p.n_ivs as usize {
                if heads[i] == heads[j] { dups += 1; }
            }
        }
        writeln!(log, "Key{} head-collisions={} (ivs={})", k_idx, dups, p.n_ivs)?;
    }
    Ok(())
}

/* §5.9.7 test7_key_sensitivity */
fn test7_key_sensitivity(log: &mut BufWriter<File>, p: &Params, keys: &[KeySlot]) -> Result<()> {
    writeln!(log, "[Test 7: Key sensitivity (avalanche)]")?;
    let n = p.bytes_per_stream;

    for (k_idx, key) in keys.iter().enumerate().take(p.n_keys as usize) {
        // fixed ts/nonce for both keys
        let (ts, nonce) = derive_ts_nonce(p.seed, k_idx as i32, 0);

        // neighbor password (flip 1 bit) — safe & stable
        let mut bytes = key.password.clone().into_bytes();
        let l = bytes.len().max(1);
        let pos = (rng_u64() as usize) % l;
        bytes[pos] ^= 0x01;
        // original password is ASCII (33..126), flipping LSB preserves valid UTF-8
        let pw2 = String::from_utf8(bytes).expect("ASCII stays valid UTF-8");

        // derive salt
        let salt32 = salt_from_ts_nonce(ts, &nonce);

        // stream A
        let (k_stream_a, ks_len_a, _km_a) = derive_okm_from_pw(&key.password, &salt32);
        let pm_a = build_postmix(&k_stream_a, ks_len_a, &nonce, ts);
        let cfg_a = generate_config_with_timestamp(&key.password, None, 0, ts)?;
        let mut a = vec![0u8; n];
        generate_stream(&cfg_a, Some(&pm_a), 0, n, &mut a)?;

        // stream B
        let (k_stream_b, ks_len_b, _km_b) = derive_okm_from_pw(&pw2, &salt32);
        let pm_b = build_postmix(&k_stream_b, ks_len_b, &nonce, ts);
        let cfg_b = generate_config_with_timestamp(&pw2, None, 0, ts)?;
        let mut b = vec![0u8; n];
        generate_stream(&cfg_b, Some(&pm_b), 0, n, &mut b)?;

        let diff = hamming_bits(&a, &b);
        writeln!(
            log,
            "Key{} avalanche bit_ratio={:.6}",
            k_idx,
            (diff as f64) / ((n as f64) * 8.0)
        )?;
    }
    Ok(())
}

/* §5.9.8 test8_tag_forgery */
fn test8_tag_forgery(log: &mut BufWriter<File>, p: &Params, keys: &[KeySlot]) -> Result<()> {
    writeln!(log, "[Test 8: Tag forgery (randomized tag must fail)]")?;
    let n = 4096usize;
    let mut pt = vec![0u8; n];
    for (i, b) in pt.iter_mut().enumerate() { *b = (i as u8) ^ 0xA5; }

    let kcap = p.n_keys.min(6) as usize;
    let ivcap = p.n_ivs.min(6) as usize;

    for k in 0..kcap {
        let key = &keys[k];
        for iv in 0..ivcap {
            let (ts, nonce) = derive_ts_nonce(p.seed, k as i32, iv as i32);
            let mut vault = scheme_encrypt_vault(key, &pt, ts, &nonce);
            // randomize 4 bytes of tag
            for _ in 0..4 {
                let pos = 61 + (rng_u32() as usize % 32);
                vault[pos] ^= (rng_u32() & 0xFF) as u8;
            }
            let rc = match scheme_decrypt_vault(key, &vault) {
                Ok(_) => 0,
                Err(code) => code,
            };
            writeln!(
                log,
                "K{} IV{} random_tag_detected={}",
                k,
                iv,
                if rc == -2 { 1 } else { 0 }
            )?;
        }
    }
    Ok(())
}

/* §5.9.9 test9_header_invariants */
fn test9_header_invariants(log: &mut BufWriter<File>, p: &Params, keys: &[KeySlot]) -> Result<()> {
    writeln!(log, "[Test 9: Header invariants]")?;
    let n = 1024usize;
    let pt = vec![0x42u8; n];
    let kcap = p.n_keys.min(6) as usize;
    let ivcap = p.n_ivs.min(6) as usize;

    for k in 0..kcap {
        let key = &keys[k];
        for iv in 0..ivcap {
            let (ts, nonce) = derive_ts_nonce(p.seed, k as i32, iv as i32);
            let vault = scheme_encrypt_vault(key, &pt, ts, &nonce);
            let salt_from_header = &vault[5..37];
            let salt_recomp = salt_from_ts_nonce(ts, &nonce);
            let ok = if salt_from_header == salt_recomp { 1 } else { 0 };
            writeln!(log, "K{} IV{} salt_ok={}", k, iv, ok)?;
        }
    }
    Ok(())
}

/// ===========================================================================
/// §5.10.0 Main
/// ===========================================================================

/* §5.10.1 main */
fn main() -> Result<()> {
    let params = parse_args();
    rng_seed(params.seed);

    let f = File::create(&params.log_path).context("open log failed")?;
    let mut log = BufWriter::new(f);

    writeln!(
        log,
        "[SARX Full-System Verdult-7]\nkeys={} ivs={} bytes={} seed=0x{:016X}\n",
        params.n_keys, params.n_ivs, params.bytes_per_stream, params.seed
    )?;

    let keys = setup_keys(params.n_keys);

    test1_aead(&mut log, &params, &keys)?;
    test2_kpa_heads(&mut log, &params, &keys)?;
    test3_seek_equivalence(&mut log, &params, &keys)?;
    test4_distinguishing(&mut log, &params, &keys)?;
    test5_bit_bias(&mut log, &params, &keys)?;
    test6_weak_keys(&mut log, &params, &keys)?;
    test7_key_sensitivity(&mut log, &params, &keys)?;
    test8_tag_forgery(&mut log, &params, &keys)?;
    test9_header_invariants(&mut log, &params, &keys)?;

    writeln!(log, "\n[Done]")?;
    log.flush()?;
    println!("Wrote {}", &params.log_path);
    Ok(())
}
