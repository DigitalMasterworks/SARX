//! §10.1.0 SARX Peripheral Roundtrip (FULL AEAD, two-phase: capture → crypto)
//! Usage:
//!   cargo run --release --bin sarx_perftest -- <device_path> [rounds=200] [chunk_mb=1]
//! Example:
//!   cargo run --release --bin sarx_perftest -- /dev/video0 200 1

use anyhow::{Context, Result};
use blake3::Hasher as Blake3;
use rand::RngCore;
use std::env;
use std::fs::File;
use std::io::Read;
use std::time::Instant;

use sarx::headers::{SARX_HEADER_BYTES, SARX_TAG_BYTES, VaultHeader, VAULT_VERSION};
use sarx::sarx::{generate_config_with_timestamp, generate_stream};

// ---- V4L2 ----
use v4l::buffer::Type as V4lBufType;
use v4l::io::mmap::Stream as V4lMmapStream;
use v4l::io::traits::CaptureStream;
use v4l::prelude::*;
use v4l::Device;

#[inline] fn u64_be(x: u64) -> [u8; 8] { x.to_be_bytes() }
#[inline] fn round_up_32(x: usize) -> usize { (x + 31) & !31 }

// simple ASCII password (>=30 cps to satisfy your guard)
fn make_password_ascii(cps: usize) -> String {
    let n = cps.clamp(30, 200);
    let mut s = String::with_capacity(n);
    let mut seed = 0xC0DEC0DEC0DEC0DEu64;
    let mut next = || {
        seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        (z ^ (z >> 31)) as u32
    };
    for _ in 0..n {
        let c = 33u8 + (next() % 94) as u8; // printable ASCII 33..126
        s.push(c as char);
    }
    s
}

fn salt_from_ts_nonce(ts_ns: u64, nonce12: &[u8; 12]) -> [u8; 32] {
    let mut inbuf = [0u8; 20];
    inbuf[..8].copy_from_slice(&u64_be(ts_ns));
    inbuf[8..20].copy_from_slice(nonce12);
    let mut out = [0u8; 32];
    let mut h = Blake3::new();
    h.update(&inbuf);
    h.finalize_xof().fill(&mut out);
    out
}

fn main() -> Result<()> {
    // Args
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "Usage: {} <device_path> [rounds=200] [chunk_mb=1]",
            args.get(0).map(|s| s.as_str()).unwrap_or("sarx_perftest")
        );
        std::process::exit(1);
    }
    let devpath = &args[1];
    let rounds: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(200);
    let chunk_mb: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1);
    let chunk = (chunk_mb.max(1)) * 1024 * 1024;

    let is_v4l = devpath.starts_with("/dev/video");

    // === FULL SYSTEM MATERIAL ===
    let pw = make_password_ascii(64); // satisfies your cps>=30 guard

    let timestamp_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos() as u64;
    let mut nonce12 = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce12);

    let salt32 = salt_from_ts_nonce(timestamp_ns, &nonce12);

    // Argon2id → OKM (k_stream || k_mac32)
    let pass_bytes = pw.as_bytes().len();
    let k_stream_len = round_up_32(pass_bytes).max(32);
    let okm_len = k_stream_len + 32;
    let mut okm = vec![0u8; okm_len];
    {
        use argon2::{Algorithm, Argon2, Params, Version};
        let params = Params::new(1 << 17, 3, 1, Some(okm_len)).unwrap(); // 128 MiB, t=3, lanes=1
        let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        a2.hash_password_into(pw.as_bytes(), &salt32, &mut okm)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    }
    let (k_stream, k_mac) = okm.split_at(k_stream_len);
    let mut k_mac32 = [0u8; 32];
    k_mac32.copy_from_slice(&k_mac[..32]);

    // Config + postmix
    let cfg = generate_config_with_timestamp(&pw, None, 0, timestamp_ns)?;
    let mut postmix = Vec::with_capacity(16 + k_stream_len + 12 + 8);
    postmix.extend_from_slice(b"SARX2DU-POST\0\0\0\0");
    postmix.extend_from_slice(k_stream);
    postmix.extend_from_slice(&nonce12);
    postmix.extend_from_slice(&u64_be(timestamp_ns));

    // Header (for AEAD domain)
    let header = VaultHeader {
        salt32,
        timestamp_ns,
        nonce12,
        t_cost: 3,
        m_cost: 17, // log2(128 MiB)
        lanes: 1,
        kdf_id: 2,  // Argon2id v1.3
    };
    let header_bytes = header.encode();

    println!(
        "[sarx_perftest] vault_params: ver=0x{:02X} cps={} ts={} nonce={:02X?} k_stream_len={} rounds={} {}",
        VAULT_VERSION,
        pw.chars().count(),
        timestamp_ns,
        &nonce12,
        k_stream_len,
        rounds,
        if is_v4l { "(v4l2 frames)" } else { "(raw read chunks)" },
    );
    println!("[sarx_perftest] password: {}", pw);

    // ============================================================
    // PHASE 1 — CAPTURE (no crypto): read rounds of data into pt_all
    // ============================================================
    let mut pt_all: Vec<u8> = Vec::new();
    let t_cap0 = Instant::now();
    let mut frames = 0usize;

    if is_v4l {
        let dev = Device::with_path(devpath)
            .with_context(|| format!("v4l2 open {}", devpath))?;

        // If you need to force format, uncomment this block:
        // use v4l::video::Capture;
        // let mut fmt = dev.format()?;
        // fmt.fourcc = v4l::FourCC::new(b"YUYV"); // or b"MJPG"
        // fmt.width  = 1280;
        // fmt.height = 720;
        // dev.set_format(&fmt)?;

        let mut stream = V4lMmapStream::with_buffers(&dev, V4lBufType::VideoCapture, 4)
            .context("v4l2: start mmap stream")?;

        while frames < rounds {
            let (buf, _meta) = stream.next().context("v4l2: next frame")?;
            if !buf.is_empty() {
                pt_all.extend_from_slice(&buf);
                frames += 1;
            }
        }
    } else {
        let mut f = File::open(devpath)
            .with_context(|| format!("open {}", devpath))?;
        let mut buf = vec![0u8; chunk];

        while frames < rounds {
            let n = f.read(&mut buf)?;
            if n == 0 { break; }
            pt_all.extend_from_slice(&buf[..n]);
            frames += 1;
        }
    }

    let cap_secs = t_cap0.elapsed().as_secs_f64();
    let cap_mb = pt_all.len() as f64 / (1024.0 * 1024.0);
    let cap_mbps = if cap_secs > 0.0 { cap_mb / cap_secs } else { f64::INFINITY };
    let cap_fps  = if is_v4l { frames as f64 / cap_secs } else { f64::NAN };
    if is_v4l {
        println!("[sarx_perftest] capture: {:.2} MB in {:.3}s → {:.2} MB/s @ {:.2} FPS",
            cap_mb, cap_secs, cap_mbps, cap_fps
        );
    } else {
        println!("[sarx_perftest] capture: {:.2} MB in {:.3}s → {:.2} MB/s",
            cap_mb, cap_secs, cap_mbps
        );
    }

    // ============================================================
    // PHASE 2 — CRYPTO (FULL AEAD): encrypt → MAC → verify → decrypt → roundtrip
    // ============================================================
    // ENCRYPT (stream keystream + XOR over captured buffer)
    let total_bytes = pt_all.len();
    let mut ct_all = vec![0u8; total_bytes];
    let mut abs_off: u64 = 0;
    let mut pos = 0usize;
    let enc_chunk = 1 * 1024 * 1024;

    let t_enc0 = Instant::now();
    while pos < total_bytes {
        let n = (total_bytes - pos).min(enc_chunk);
        let mut ks = vec![0u8; n];
        generate_stream(&cfg, Some(&postmix), abs_off, n, &mut ks)?;
        for i in 0..n { ct_all[pos + i] = pt_all[pos + i] ^ ks[i]; }
        pos += n;
        abs_off += n as u64;
    }
    let enc_secs = t_enc0.elapsed().as_secs_f64();

    // MAC finalize (len then ciphertext)
    let mut mac = Blake3::new_keyed(&k_mac32);
    mac.update(b"SARX2DU-MAC-v1");
    mac.update(&header_bytes);
    mac.update(&(total_bytes as u64).to_le_bytes());
    mac.update(&ct_all);
    let mut tag = [0u8; 32];
    mac.finalize_xof().fill(&mut tag);

    // VERIFY TAG (like decrypt path)
    let mut mac2 = Blake3::new_keyed(&k_mac32);
    mac2.update(b"SARX2DU-MAC-v1");
    mac2.update(&header_bytes);
    mac2.update(&(total_bytes as u64).to_le_bytes());
    mac2.update(&ct_all);
    let mut tag_check = [0u8; 32];
    mac2.finalize_xof().fill(&mut tag_check);
    if tag != tag_check {
        anyhow::bail!("MAC mismatch (tag verify failed)");
    }

    // DECRYPT (stream keystream + XOR)
    let t_dec0 = Instant::now();
    let mut pt2 = vec![0u8; total_bytes];
    let mut off: u64 = 0;
    let mut pos2 = 0usize;
    let dec_chunk = 1 * 1024 * 1024;
    while pos2 < total_bytes {
        let n = (total_bytes - pos2).min(dec_chunk);
        let mut ks = vec![0u8; n];
        generate_stream(&cfg, Some(&postmix), off, n, &mut ks)?;
        for i in 0..n { pt2[pos2 + i] = ct_all[pos2 + i] ^ ks[i]; }
        pos2 += n;
        off += n as u64;
    }
    let dec_secs = t_dec0.elapsed().as_secs_f64();

    // ROUNDTRIP CHECK
    if pt_all != pt2 {
        anyhow::bail!("roundtrip mismatch: decrypted != original");
    }

    // RESULTS
    let mb = (total_bytes as f64) / (1024.0 * 1024.0);
    let enc_mbps = if enc_secs > 0.0 { mb / enc_secs } else { f64::INFINITY };
    let dec_mbps = if dec_secs > 0.0 { mb / dec_secs } else { f64::INFINITY };

    println!(
        "[sarx_perftest] crypto: enc={:.3}s ({:.2} MB/s) • dec={:.3}s ({:.2} MB/s) • bytes={:.2} MB",
        enc_secs, enc_mbps, dec_secs, dec_mbps, mb
    );
    println!(
        "[sarx_perftest] header={}B tag={}B (BLAKE3 keyed) • ver=0x{:02X}",
        SARX_HEADER_BYTES, SARX_TAG_BYTES, VAULT_VERSION
    );

    Ok(())
}
