/* =============================================================================
 * SARX — sarx_bench_stream.rs — Program v4.1.0
 * Numbering: Sections §4.X.0, Subsections §4.X.Y (code-only labels)
 * Purpose: Parallel streaming keystream/ENC/DEC throughput benchmark (ARX-only).
 * =============================================================================
*/

// ============================================================================
// §4.1.0 Imports
// ============================================================================
use anyhow::Result;
use blake3::Hasher as Blake3;
use rayon::prelude::*;
use zeroize::Zeroize;
use rand::RngCore;
use std::env;
use std::fs::File;
use std::io::Read;
use std::time::Instant;
use sarx::headers::VaultHeader;
use sarx::sarx::{generate_config_with_timestamp, generate_stream};

// ============================================================================
// §4.2.0 Small Helpers
// ============================================================================
/* §4.2.1 u64_be: big-endian u64 bytes */
fn u64_be(x: u64) -> [u8; 8] { x.to_be_bytes() }

/* §4.2.2 round_up_32: next multiple of 32 */
fn round_up_32(x: usize) -> usize { (x + 31) & !31 }

/* §4.2.3 random_unicode_password: printable Unicode (no surrogates) */
fn random_unicode_password(min_cps: usize, max_cps: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let target = rng.gen_range(min_cps..=max_cps);
    let mut s = String::new();
    let mut cps = 0usize;
    while cps < target {
        let cp = loop {
            let r1: u32 = rng.gen();
            let r2: u32 = rng.gen();
            let v = (r1 ^ (r2 << 1)) % 0x110000;
            if !(0xD800..=0xDFFF).contains(&v) && v >= 0x20 { break v; }
        };
        if let Some(ch) = char::from_u32(cp) { s.push(ch); cps += 1; }
    }
    s
}

// ============================================================================
// §4.3.0 main: Benchmark Entry
// ============================================================================
fn main() -> Result<()> {
    /* §4.3.1 data size from env (SARX_MB, default 100 MB) */
    let mb_env = env::var("SARX_MB").ok();
    let mb: usize = mb_env
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let data_size = mb * 1024 * 1024;

    /* §4.3.2 random password */
    let password = random_unicode_password(30, 101);

    /* §4.3.3 timestamp + nonce12 */
    let timestamp_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?.as_nanos() as u64;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);

    /* §4.3.4 salt32 = BLAKE3(timestamp || nonce) */
    let mut salt_in = [0u8; 20];
    salt_in[..8].copy_from_slice(&u64_be(timestamp_ns));
    salt_in[8..].copy_from_slice(&nonce);
    let mut hh = Blake3::new();
    hh.update(&salt_in);
    let mut salt32 = [0u8; 32];
    hh.finalize_xof().fill(&mut salt32);

    /* §4.3.5 Argon2id KDF → OKM (k_stream || k_mac32) */
    let pass_bytes = password.as_bytes().len();
    let k_stream_len = round_up_32(pass_bytes).max(32);
    let okm_len = k_stream_len + 32;
    let mut okm = vec![0u8; okm_len];
    {
        use argon2::{Argon2, Params, Algorithm, Version};
        let params = Params::new(1 << 17, 3, 1, Some(okm_len)).unwrap();
        let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        a2.hash_password_into(password.as_bytes(), &salt32, &mut okm)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    }

    // Split Argon2 OKM into k_stream || k_mac32 (k_stream is unused by ARX keystream, but kept for parity)
    let (_k_stream, k_mac) = okm.split_at(k_stream_len);
    let mut k_mac32 = [0u8; 32];
    k_mac32.copy_from_slice(&k_mac[..32]);

    // Build VaultHeader (same as encryptor)
    let header = VaultHeader {
        salt32,
        timestamp_ns,
        nonce12: nonce,
        t_cost: 3,
        m_cost: 17,
        lanes: 1,
        kdf_id: 2,
    };
    let header_raw = header.encode();

    /* §4.3.6 config (ARX-only keystream seeded by password+timestamp) */
    let cfg = generate_config_with_timestamp(&password, None, 0, timestamp_ns)?;

    /* §4.3.7 buffers + random plaintext */
    let mut plain = vec![0u8; data_size];
    let mut ct = vec![0u8; data_size];
    let mut pt2 = vec![0u8; data_size];
    File::open("/dev/urandom")?.read_exact(&mut plain)?;

    /* §4.3.8 hardware + thread sweep */
    let hw = num_cpus::get();
    let sweep = [1, 2, 4, 6, 8, 12];

    println!("[sarx_bench_stream] Parallel stream: {} HW threads, data={} MB",
        hw, data_size/(1024*1024));
    println!("THREADS\tKS(MB/s)\tENC(MB/s)\tDEC(MB/s)\tRoundtrip(ms)\tOK");

    /* §4.3.9 benchmark loop: KS / ENC / DEC */
    // -- ARM/Pi platform check --
    let is_arm = matches!(std::env::consts::ARCH, "arm" | "aarch64");

    if is_arm {
        println!("⚠️  [VelvetSafe Benchmark] ARM/Pi detected — timing results may be inaccurate on some hardware (clock granularity, thread pool). For best accuracy, set SARX_MB=32 and run with 1 thread.");
    }
    for &th in &sweep {
        let threads = th.min(hw);

        if is_arm && th > 1 {
            println!("  [ARM/Pi] Skipping {th} threads (Rayon/threadpool timing can be unreliable on ARM/Pi); use 1 thread for reliable results.");
            continue;
        }

        // §4.3.9.1 KS only (ARX-256, no postmix)
        let mut ks_buf = vec![0u8; data_size];
        let t0 = Instant::now();
        ks_buf.par_chunks_mut(data_size/threads)
            .enumerate()
            .for_each(|(i, chunk)| {
                let start = (i * chunk.len()) as u64;
                generate_stream(&cfg, None, start, chunk.len(), chunk).unwrap();
            });
        let t_ks = t0.elapsed().as_secs_f64();
        let ks_mbps = (data_size as f64 / (1024.0*1024.0)) / t_ks;
        ks_buf.zeroize();

        // §4.3.9.2 ENC
        let mut ks = vec![0u8; data_size];
        let t0 = Instant::now();
        ks.par_chunks_mut(data_size/threads)
            .enumerate()
            .for_each(|(i, chunk)| {
                let start = (i * chunk.len()) as u64;
                generate_stream(&cfg, None, start, chunk.len(), chunk).unwrap();
            });
        for i in 0..data_size { ct[i] = plain[i] ^ ks[i]; }
        let t_enc = t0.elapsed().as_secs_f64();

        // MAC over header + length + ciphertext (unchanged)
        let mut mac_enc = blake3::Hasher::new_keyed(&k_mac32);
        mac_enc.update(b"SARX2DU-MAC-v1");
        mac_enc.update(&header_raw);
        mac_enc.update(&(data_size as u64).to_le_bytes());
        mac_enc.update(&ct);
        let mut tag_enc = [0u8; 32];
        mac_enc.finalize_xof().fill(&mut tag_enc);

        // §4.3.9.3 DEC
        let t0 = Instant::now();
        ks.par_chunks_mut(data_size/threads)
            .enumerate()
            .for_each(|(i, chunk)| {
                let start = (i * chunk.len()) as u64;
                generate_stream(&cfg, None, start, chunk.len(), chunk).unwrap();
            });

        // verify MAC
        let mut mac_dec = blake3::Hasher::new_keyed(&k_mac32);
        mac_dec.update(b"SARX2DU-MAC-v1");
        mac_dec.update(&header_raw);
        mac_dec.update(&(data_size as u64).to_le_bytes());
        mac_dec.update(&ct);
        let mut tag_dec = [0u8; 32];
        mac_dec.finalize_xof().fill(&mut tag_dec);
        assert_eq!(tag_enc, tag_dec, "MAC mismatch");

        // decrypt
        for i in 0..data_size { pt2[i] = ct[i] ^ ks[i]; }
        let t_dec = t0.elapsed().as_secs_f64();

        ks.zeroize();

        // §4.3.9.4 results
        let ok = plain == pt2;
        let mb = data_size as f64 / (1024.0*1024.0);
        let enc_mbps = mb / t_enc;
        let dec_mbps = mb / t_dec;
        let roundtrip_ms = (t_enc + t_dec) * 1000.0;

        println!("{threads}\t{ks_mbps:.2}\t\t{enc_mbps:.2}\t\t{dec_mbps:.2}\t\t{roundtrip_ms:.3}\t\t{}",
            if ok { "YES" } else { "NO" });
    }

    /* §4.3.10 hygiene: wipe sensitive buffers */
    plain.zeroize();
    ct.zeroize();
    pt2.zeroize();
    okm.zeroize();
    salt32.zeroize();
    Ok(())
}
