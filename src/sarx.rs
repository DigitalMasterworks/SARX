//! §1.1.0 Overview — SARX core library (Rust mirror of your C)
//! - Config generation (UTF-8 substring table + base_key32)
//! - ARX-256 keystream keyed only by base_key32
//! - Encrypt/Decrypt wrappers
//! - Streaming keystream with offset (CTR-style)

/* =============================================================================
 * SARX — sarx.rs — Program v1.1.0
 * Numbering: Program=1.1.0, Sections=§1.X.0, Subsections=§1.X.Y
 * =============================================================================
 */

// ============================================================================
// §1.2.0 Imports & Crate Uses
// ============================================================================
use anyhow::{bail, Result};
use blake3::Hasher as Blake3;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::headers::SARX_CHUNK;
use crate::substrate_arx::arx256_fill;

// ============================================================================
// §1.3.0 Primitives & Helpers
// Purpose: zeroization, tiny helpers, legacy parity functions.
// ============================================================================

/* §1.3.1 secure_zero */
#[inline]
fn secure_zero(buf: &mut [u8]) { buf.zeroize(); }

/* §1.3.2 Small Helpers (group marker) */

/* §1.3.21 be64: big-endian u64 */
#[inline]
fn be64(x: u64) -> [u8; 8] { x.to_be_bytes() }

/* §1.3.22 blake3_hash32: 32-byte XOF read */
#[inline]
fn blake3_hash32(data: &[u8]) -> [u8; 32] {
    let mut h = Blake3::new();
    if !data.is_empty() { h.update(data); }
    let mut out = [0u8; 32];
    h.finalize_xof().fill(&mut out);
    out
}

/* §1.3.23 sha256 (legacy parity) */
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut a = [0u8; 32]; a.copy_from_slice(&out); a
}

/* §1.3.24 hmac_sha256 (legacy parity) */
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut a = [0u8; 32]; a.copy_from_slice(&out); a
}

/* §1.3.25 hkdf_sha256 (legacy parity) */
pub fn hkdf_sha256(ikm: &[u8], salt: Option<&[u8]>, info: Option<&[u8]>, okm_len: usize) -> Vec<u8> {
    let hk = match salt {
        Some(s) => Hkdf::<Sha256>::new(Some(s), ikm),
        None    => Hkdf::<Sha256>::new(None, ikm),
    };
    let mut out = vec![0u8; okm_len.max(1)];
    hk.expand(info.unwrap_or(&[]), &mut out).expect("HKDF expand");
    out
}

// ============================================================================
// §1.4.0 BLAKE3 KDF & MAC
// ============================================================================
/* §1.4.1 kdf_blake3_split: derive (k_stream, k_mac) */
pub fn kdf_blake3_split(secret32: &[u8; 32], salt32: Option<&[u8; 32]>) -> ([u8; 32], [u8; 32]) {
    // ikm = blake3(secret || salt?)
    let mut hh = Blake3::new();
    hh.update(secret32);
    if let Some(s) = salt32 { hh.update(s); }
    let mut ikm = [0u8; 32]; hh.finalize_xof().fill(&mut ikm);

    // derive k_stream
    let mut h1 = blake3::Hasher::new_derive_key("SARX k_stream v1");
    h1.update(&ikm);
    let mut k_stream = [0u8; 32]; h1.finalize_xof().fill(&mut k_stream);

    // derive k_mac
    let mut h2 = blake3::Hasher::new_derive_key("SARX k_mac v1");
    h2.update(&ikm);
    let mut k_mac = [0u8; 32]; h2.finalize_xof().fill(&mut k_mac);

    ikm.zeroize();
    (k_stream, k_mac)
}

/* §1.4.2 sarx_mac_blake3: keyed XOF tag */
pub fn sarx_mac_blake3(k_mac32: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(k_mac32);
    if !msg.is_empty() { h.update(msg); }
    let mut out = [0u8; 32];
    h.finalize_xof().fill(&mut out);
    out
}

// ============================================================================
// §1.5.0 Configuration Objects
// ============================================================================
/* §1.5.1 SARXConfig struct + Drop */
#[derive(Clone)]
pub struct SARXConfig {
    /// 256-bit base key for the ARX-256 stream, derived from password + timestamp.
    pub base_key32: [u8; 32],
}

impl Drop for SARXConfig {
    fn drop(&mut self) {
        self.base_key32.zeroize();
    }
}

// ============================================================================
// §1.6.0 Config Generation
// ============================================================================
/* §1.6.1 generate_config_with_timestamp */
pub fn generate_config_with_timestamp(password: &str,
                                      _plaintext: Option<&[u8]>,
                                      _plen: usize,
                                      ts_ns: u64) -> Result<SARXConfig> {
    // base_key32 = BLAKE3(password || ts_be)
    let mut h = Blake3::new();
    h.update(password.as_bytes());
    h.update(&be64(ts_ns));
    let mut base_key32 = [0u8; 32];
    h.finalize_xof().fill(&mut base_key32);
    Ok(SARXConfig { base_key32 })
}

/* §1.6.2 generate_config (now) */
pub fn generate_config(password: &str, plaintext: Option<&[u8]>, plen: usize) -> Result<SARXConfig> {
    let ts_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap()
        .as_nanos() as u64;
    generate_config_with_timestamp(password, plaintext, plen, ts_ns)
}

// ============================================================================
// §1.8.0 Core Keystream
// ============================================================================

/* §1.8.1 generate_keystream — convenience, offset = 0 */
pub fn generate_keystream(cfg: &SARXConfig, length: usize, out: &mut [u8]) -> Result<()> {
    // Pure ARX-256 keystream, no postmix, starting at offset 0.
    generate_stream(cfg, None, 0, length, out)
}

// ============================================================================
// §1.9.0 Postmix Mask (disabled)
// ============================================================================

/* §1.9.1 apply_final_mask — no-op in ARX-only v1.1.0 */
pub fn apply_final_mask(_keystream: &mut [u8], _postmix: Option<&[u8]>) -> Result<()> {
    // Postmix layer is intentionally disabled: keystream is "honest" ARX-256 only.
    Ok(())
}

// ============================================================================
// §1.10.0 Encrypt / Decrypt Wrappers
// ============================================================================
/* §1.10.1 encrypt_sarx */
pub fn encrypt_sarx(pt: &[u8], cfg: &SARXConfig, _postmix: Option<&[u8]>, ct: &mut [u8]) -> Result<()> {
    if pt.len() != ct.len() { bail!("len mismatch"); }
    let mut ks = vec![0u8; pt.len().max(1)];
    // Directly produce keystream from ARX-256 at offset 0 (postmix ignored).
    generate_stream(cfg, None, 0, pt.len(), &mut ks)?;
    for i in 0..pt.len() { ct[i] = pt[i] ^ ks[i]; }
    secure_zero(&mut ks);
    Ok(())
}

/* §1.10.2 decrypt_sarx (xor-symmetric) */
pub fn decrypt_sarx(ct: &[u8], cfg: &SARXConfig, postmix: Option<&[u8]>, pt: &mut [u8]) -> Result<()> {
    encrypt_sarx(ct, cfg, postmix, pt)
}

// ============================================================================
// §1.11.0 Streaming Keystream (ARX-256 CTR mode)
// ============================================================================

/* §1.11.3 generate_stream — ARX-only, postmix ignored */
pub fn generate_stream(cfg: &SARXConfig,
                       _postmix: Option<&[u8]>,
                       offset: u64,
                       length: usize,
                       out: &mut [u8]) -> Result<()> {
    if out.len() < length { bail!("bad args"); }
    if length == 0 { return Ok(()); }

    // Interpret base_key32 as four little-endian u64 words.
    let k0 = u64::from_le_bytes(cfg.base_key32[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(cfg.base_key32[8..16].try_into().unwrap());
    let k2 = u64::from_le_bytes(cfg.base_key32[16..24].try_into().unwrap());
    let k3 = u64::from_le_bytes(cfg.base_key32[24..32].try_into().unwrap());

    // Base counter = 0; byte-level offset handled inside arx256_fill.
    let ctr0: u64 = 0;

    arx256_fill((k0, k1, k2, k3), ctr0, offset, &mut out[..length]);

    Ok(())
}

// ============================================================================
// §1.12.0 Thermodynamic KDF hardening helper
// ============================================================================

/// Scratch size for thermo-hardening (per KDF run).
/// Tune as needed; 512 MiB matches your earlier experiment.
pub const THERMO_SCRATCH_MIB: usize = 512;

/// Number of random-walk steps over the scratch buffer.
pub const THERMO_WALK_STEPS: usize = 1_000_000;

/// In-place OKM hardening: uses OKM as a seed, performs a large ARX-style
/// random walk over a deterministic scratch buffer, then folds a BLAKE3 digest
/// of that scratch back into OKM.
///
/// Encrypt and decrypt both call this so it must be fully deterministic
/// given `okm`.
pub fn thermo_harden_okm(okm: &mut [u8]) {
    use zeroize::Zeroize;

    // ---- Seed from OKM via BLAKE3 ----
    let mut seed = [0u8; 32];
    {
        let mut h = Blake3::new();
        h.update(b"SARX2DU-THERMO-SEED-v1");
        h.update(okm);
        h.finalize_xof().fill(&mut seed);
    }

    // ---- Deterministically fill scratch buffer ----
    let scratch_len_u64 = (THERMO_SCRATCH_MIB * 1024 * 1024) / 8;
    let mut scratch = vec![0u64; scratch_len_u64];

    {
        let mut h = Blake3::new();
        h.update(b"SARX2DU-THERMO-SCRATCH-v1");
        h.update(&seed);
        let mut xof = h.finalize_xof();
        let mut tmp = [0u8; 8];
        for slot in &mut scratch {
            xof.fill(&mut tmp);
            *slot = u64::from_le_bytes(tmp);
        }
    }

    // ---- ARX random walk keyed by seed ----
    let mut x0 = u64::from_le_bytes(seed[0..8].try_into().unwrap());
    let mut x1 = u64::from_le_bytes(seed[8..16].try_into().unwrap());
    let mut x2 = u64::from_le_bytes(seed[16..24].try_into().unwrap());
    let mut x3 = u64::from_le_bytes(seed[24..32].try_into().unwrap());
    let mask = (scratch_len_u64 as u64) - 1;

    for _ in 0..THERMO_WALK_STEPS {
        x0 = x0.wrapping_add(x1.rotate_left(13));
        x1 ^= x2.rotate_left(27);
        x2 = x2.wrapping_add(x3.rotate_left(17));
        x3 ^= x0.rotate_left(5);

        let idx = (x0 ^ x2 ^ x3) & mask;
        let v = scratch[idx as usize];
        let new_v = v
            .wrapping_add(x1)
            ^ x2.rotate_left(11)
            ^ x3.rotate_right(7);
        scratch[idx as usize] = new_v;
    }

    // ---- Compress scratch and fold into OKM ----
    let mut mix = [0u8; 32];
    {
        let mut h = Blake3::new();
        h.update(b"SARX2DU-THERMO-MIX-v1");
        let mut tmp = [0u8; 8];
        // We don't need to hash all 512 MiB byte-for-byte; sampling still forces
        // the walk to execute.
        for chunk in scratch.chunks(1024) {
            for &v in chunk {
                tmp = v.to_le_bytes();
                h.update(&tmp);
            }
        }
        h.finalize_xof().fill(&mut mix);
    }

    for (i, b) in okm.iter_mut().enumerate() {
        *b ^= mix[i % 32];
    }

    scratch.zeroize();
    seed.zeroize();
}
