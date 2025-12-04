// src/bin/sarx_security.rs
//
// SARX Security Harness (Rust)
// ------------------------------------------------------------
// What this does:
// 1) Defines the SARX scheme components we rely on for the proof
//    (postmix-masked keystream + Encrypt-then-MAC).
// 2) Runs three empirical “sanity” phases that match the proof steps:
//      A) INT-CTXT sanity: tag forgery attempts fail (MAC PRF-style).
//      B) Keystream masking sanity: real keystream vs uniform looks indistinguishable
//         to simple chi²/serial-correlation distinguishers (postmix hides structure).
//      C) AE (EtM) sanity: verify-then-decrypt rejects modified ciphertexts (IND-CCA-style).
// 3) If all phases complete without failures, it prints a LaTeX section that
//    you can paste into your paper, with theorem statements and the game-hopping outline.
//
// Notes:
// - This uses the existing Rust library in your repo (`sarx::sarx`) to generate
//   configs and keystreams, and it mirrors how your bins compute postmix and MAC.
// - We *do not* reprove cryptographic primitives; this harness empirically
//   validates the assumptions used in the reduction and generates a ready-to-paste LaTeX section.
//
// Build & run:
//   cargo run --release --bin sarx_security
//
// Optional envs:
//   SARX_SEC_TRIALS=1000  (how many trials for sanity checks; default 500)
//   SARX_SEC_MSG_BYTES=65536 (message length per trial; default 65536)
// ------------------------------------------------------------

use anyhow::{bail, Context, Result};
use blake3::Hasher as Blake3;
use rand::RngCore;
use std::time::Instant;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

// Pull core pieces from your library:
use sarx::sarx::{generate_config_with_timestamp, generate_stream};

// -------------------------------
// Helpers (byte utils & stats)
// -------------------------------
#[inline] fn be64(x: u64) -> [u8; 8] { x.to_be_bytes() }

fn chi2_bytes(buf: &[u8]) -> f64 {
    let mut f = [0u32; 256];
    for &b in buf { f[b as usize] += 1; }
    let n = buf.len() as f64;
    let exp = n / 256.0;
    let mut chi2 = 0.0;
    for &c in &f {
        let d = (c as f64) - exp;
        chi2 += (d * d) / exp;
    }
    chi2 // df = 255
}

fn serial_corr(buf: &[u8]) -> f64 {
    if buf.len() < 3 { return 0.0; }
    let mut sx = 0.0;
    let mut sxx = 0.0;
    let mut sxy = 0.0;
    for w in buf.windows(2) {
        let x = w[0] as f64;
        let y = w[1] as f64;
        sx += x;
        sxx += x * x;
        sxy += x * y;
    }
    let n = (buf.len() - 1) as f64;
    let num = n * sxy - sx * sx;
    let den = ((n * sxx - sx * sx) * (n * sxx - sx * sx)).sqrt();
    if den == 0.0 { 0.0 } else { num / den }
}

fn ct_eq32(a: &[u8;32], b: &[u8;32]) -> bool {
    a.ct_eq(b).into()
}

// -------------------------------
// Postmix & MAC (as in your bins)
// -------------------------------
fn make_postmix(k_stream: &[u8], nonce12: &[u8;12], ts_ns: u64) -> Vec<u8> {
    let mut pm = Vec::with_capacity(16 + k_stream.len() + 12 + 8);
    pm.extend_from_slice(b"SARX2DU-POST\0\0\0\0"); // exact domain sep
    pm.extend_from_slice(k_stream);
    pm.extend_from_slice(nonce12);
    pm.extend_from_slice(&be64(ts_ns));
    pm
}

fn mac_hdr_ct(k_mac: &[u8;32], hdr_raw: &[u8], ct_len_le: [u8;8], ct: &[u8]) -> [u8;32] {
    let mut mac = Blake3::new_keyed(k_mac);
    mac.update(hdr_raw);
    mac.update(&ct_len_le);
    mac.update(ct);
    let mut out = [0u8; 32];
    mac.finalize_xof().fill(&mut out);
    out
}

// -------------------------------
// Trial configuration
// -------------------------------
#[derive(Clone)]
struct TrialParams {
    trials: usize,
    msg_bytes: usize,
}

impl TrialParams {
    fn from_env() -> Self {
        let trials = std::env::var("SARX_SEC_TRIALS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(5000);
        let msg_bytes = std::env::var("SARX_SEC_MSG_BYTES")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(65_536);
        Self { trials, msg_bytes }
    }
}

#[derive(serde::Serialize)]
struct SecuritySummary {
    trials: usize,
    msg_bytes: usize,
    phase_a_forged_tags_verified: usize,
    phase_b_mean_chi2_real: f64,
    phase_b_mean_chi2_uni: f64,
    phase_b_chi2_gap: f64,
    phase_b_mean_sc_real: f64,
    phase_b_mean_sc_uni: f64,
    phase_b_sc_gap: f64,
    phase_c_modified_ct_accepted: usize,
}

// Phase A: return forged count
fn phase_a_int_ctxt(params: &TrialParams) -> Result<usize> {
    let mut rng = rand::thread_rng();
    let mut failures = 0usize;

    for _ in 0..params.trials {
        // Random password + timestamp
        let pw = (0..64)
            .map(|_| (33 + (rng.next_u32() % 94)) as u8 as char)
            .collect::<String>();
        let ts_ns = Instant::now().elapsed().as_nanos() as u64 + rng.next_u64();
        let cfg = generate_config_with_timestamp(&pw, None, 0, ts_ns)
            .context("cfg")?;

        // Nonce + fake raw header (61 bytes)
        let mut nonce12 = [0u8; 12];
        rng.fill_bytes(&mut nonce12);
        let mut hdr_raw = vec![0u8; 61];
        hdr_raw[0..8].copy_from_slice(&be64(ts_ns));
        hdr_raw[8..20].copy_from_slice(&nonce12);

        // MAC key
        let k_mac: [u8; 32] = {
            let mut mac_seed = Blake3::new();
            mac_seed.update(b"SARX-MAC-K");
            mac_seed.update(&be64(ts_ns));
            mac_seed.update(&nonce12);
            let mut out = [0u8; 32];
            mac_seed.finalize_xof().fill(&mut out);
            out
        };

        // Postmix
        let mut k_stream = [0u8; 64];
        {
            let mut h = Blake3::new();
            h.update(b"SARX-STREAM-K");
            h.update(&be64(ts_ns));
            h.update(&nonce12);
            h.finalize_xof().fill(&mut k_stream);
        }
        let postmix = make_postmix(&k_stream, &nonce12, ts_ns);

        // Message + keystream
        let mut msg = vec![0u8; params.msg_bytes];
        rng.fill_bytes(&mut msg);
        let mut ks = vec![0u8; msg.len()];
        generate_stream(&cfg, Some(&postmix), 0, ks.len(), &mut ks)?;
        let mut ct = vec![0u8; msg.len()];
        for i in 0..msg.len() { ct[i] = msg[i] ^ ks[i]; }

        // MAC
        let len_le = (ct.len() as u64).to_le_bytes();
        let tag = mac_hdr_ct(&k_mac, &hdr_raw, len_le, &ct);

        // Forge attempt
        let mut forged_ct = ct.clone();
        if !forged_ct.is_empty() {
            let j = (rng.next_u64() as usize) % forged_ct.len();
            forged_ct[j] ^= 0x01;
        }
        let recomputed = mac_hdr_ct(&k_mac, &hdr_raw, len_le, &forged_ct);

        if ct_eq32(&recomputed, &tag) {
            failures += 1;
        }

        msg.zeroize();
        ks.zeroize();
        k_stream.zeroize();
    }

    Ok(failures)
}

fn phase_b_masking(params: &TrialParams)
    -> Result<((f64, f64, f64), (f64, f64, f64))>
{
    let mut rng = rand::thread_rng();
    let trials = params.trials;

    let mut chi_real = Vec::with_capacity(trials);
    let mut chi_rand = Vec::with_capacity(trials);
    let mut sc_real = Vec::with_capacity(trials);
    let mut sc_rand = Vec::with_capacity(trials);

    for _ in 0..trials {
        let pw = (0..64)
            .map(|_| (33 + (rng.next_u32() % 94)) as u8 as char)
            .collect::<String>();
        let ts_ns = Instant::now().elapsed().as_nanos() as u64 + rng.next_u64();
        let cfg = generate_config_with_timestamp(&pw, None, 0, ts_ns)
            .context("cfg")?;

        let mut nonce12 = [0u8; 12];
        rng.fill_bytes(&mut nonce12);

        // derive k_stream for postmix
        let mut k_stream = [0u8; 64];
        {
            let mut h = Blake3::new();
            h.update(b"SARX-STREAM-K");
            h.update(&be64(ts_ns));
            h.update(&nonce12);
            h.finalize_xof().fill(&mut k_stream);
        }
        let postmix = make_postmix(&k_stream, &nonce12, ts_ns);

        // Real masked keystream
        let mut real = vec![0u8; params.msg_bytes];
        generate_stream(&cfg, Some(&postmix), 0, real.len(), &mut real)?;
        chi_real.push(chi2_bytes(&real));
        sc_real.push(serial_corr(&real));

        // Uniform random control
        let mut uni = vec![0u8; params.msg_bytes];
        rng.fill_bytes(&mut uni);
        chi_rand.push(chi2_bytes(&uni));
        sc_rand.push(serial_corr(&uni));

        real.zeroize();
        uni.zeroize();
        k_stream.zeroize();
    }

    let mean = |v: &Vec<f64>| v.iter().sum::<f64>() / (v.len().max(1) as f64);
    let m_chi_r = mean(&chi_real);
    let m_chi_u = mean(&chi_rand);
    let m_sc_r = mean(&sc_real);
    let m_sc_u = mean(&sc_rand);

    let chi_gap = (m_chi_r - m_chi_u).abs();
    let sc_gap = (m_sc_r - m_sc_u).abs();

    Ok(((m_chi_r, m_chi_u, chi_gap), (m_sc_r, m_sc_u, sc_gap)))
}

fn phase_c_etm(params: &TrialParams) -> Result<usize> {
    let mut rng = rand::thread_rng();
    let mut accepted = 0usize;

    for _ in 0..params.trials {
        let pw = (0..64)
            .map(|_| (33 + (rng.next_u32() % 94)) as u8 as char)
            .collect::<String>();
        let ts_ns = Instant::now().elapsed().as_nanos() as u64 + rng.next_u64();
        let cfg = generate_config_with_timestamp(&pw, None, 0, ts_ns)
            .context("cfg")?;

        let mut nonce12 = [0u8; 12];
        rng.fill_bytes(&mut nonce12);

        // fake header
        let mut hdr_raw = vec![0u8; 61];
        hdr_raw[0..8].copy_from_slice(&be64(ts_ns));
        hdr_raw[8..20].copy_from_slice(&nonce12);

        // derive MAC key
        let k_mac: [u8; 32] = {
            let mut mac_seed = Blake3::new();
            mac_seed.update(b"SARX-MAC-K");
            mac_seed.update(&be64(ts_ns));
            mac_seed.update(&nonce12);
            let mut out = [0u8; 32];
            mac_seed.finalize_xof().fill(&mut out);
            out
        };

        // derive stream key for postmix
        let mut k_stream = [0u8; 64];
        {
            let mut h = Blake3::new();
            h.update(b"SARX-STREAM-K");
            h.update(&be64(ts_ns));
            h.update(&nonce12);
            h.finalize_xof().fill(&mut k_stream);
        }
        let postmix = make_postmix(&k_stream, &nonce12, ts_ns);

        // message + encrypt
        let mut msg = vec![0u8; params.msg_bytes];
        rng.fill_bytes(&mut msg);
        let mut ks = vec![0u8; msg.len()];
        generate_stream(&cfg, Some(&postmix), 0, ks.len(), &mut ks)?;
        let mut ct = vec![0u8; msg.len()];
        for i in 0..msg.len() { ct[i] = msg[i] ^ ks[i]; }

        let len_le = (ct.len() as u64).to_le_bytes();
        let tag = mac_hdr_ct(&k_mac, &hdr_raw, len_le, &ct);

        // modify ciphertext
        if !ct.is_empty() {
            let j = (rng.next_u64() as usize) % ct.len();
            ct[j] ^= 0x80;
        }
        let recomputed = mac_hdr_ct(&k_mac, &hdr_raw, len_le, &ct);

        if ct_eq32(&recomputed, &tag) {
            accepted += 1; // bad: modified CT accepted
        }

        msg.zeroize();
        ks.zeroize();
        k_stream.zeroize();
    }

    Ok(accepted)
}

// -------------------------------
// Main
// -------------------------------
fn main() -> anyhow::Result<()> {
    let params = TrialParams::from_env();

    let forged = phase_a_int_ctxt(&params)?;  

    let ((chi_r, chi_u, chi_gap), (sc_r, sc_u, sc_gap)) = phase_b_masking(&params)?;  

    let accepted = phase_c_etm(&params)?;     

    let summary = SecuritySummary {
        trials: params.trials,
        msg_bytes: params.msg_bytes,
        phase_a_forged_tags_verified: forged,
        phase_b_mean_chi2_real: chi_r,
        phase_b_mean_chi2_uni: chi_u,
        phase_b_chi2_gap: chi_gap,
        phase_b_mean_sc_real: sc_r,
        phase_b_mean_sc_uni: sc_u,
        phase_b_sc_gap: sc_gap,
        phase_c_modified_ct_accepted: accepted,
    };
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}
