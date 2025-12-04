//! §2.1.0 Overview — CLI: encrypt file → write .vault (61B header + 32B tag + ciphertext)
//! - Random Unicode password to stdout/TTY behavior (parity)
//! - Argon2id kdf (t=3, m=2^17 KiB, lanes=1) → k_stream||k_mac
//! - Header encode, MAC domain, streaming XOR with parallel slices
//! - Durability: fsync vault before deleting plaintext

/* =============================================================================
 * SARX — sarx_encrypt.rs — Program v2.0.0
 * Numbering: Sections §2.X.0, Subsections §2.X.Y (code-only labels)
 * =============================================================================
 */

// ============================================================================
// §2.2.0 Imports & TLS State
// ============================================================================
use anyhow::{Context, Result};
use blake3::Hasher as Blake3;
use rayon::prelude::*;
use zeroize::Zeroize;

use rand::RngCore;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::cell::RefCell;

use sarx::{
    headers::{SARX_TAG_BYTES, VaultHeader},
    sarx::{generate_stream, generate_config_with_timestamp, thermo_harden_okm},
};

/* §2.2.1 THREAD-LOCAL keystream scratch */
thread_local! {
    static TLS_KS: RefCell<Vec<u8>> = RefCell::new(Vec::new());
}

// ============================================================================
// §2.3.0 Small Helpers
// ============================================================================

/* §2.3.1 u64_be: big-endian u64 bytes */
#[inline] fn u64_be(x: u64) -> [u8; 8] { x.to_be_bytes() }

/* §2.3.2 round_up_32: next multiple of 32 */
#[inline] fn round_up_32(x: usize) -> usize { (x + 31) & !31 }

/* §2.3.3 random_unicode_password: printable Unicode (no surrogates) */
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

/* §2.3.4 xor_bytes_into: XOR a^b into dst */
// Replace the old helper:
#[inline]
fn xor_inplace(dst: &mut [u8], ks: &[u8]) {
    for i in 0..dst.len() {
        dst[i] ^= ks[i];
    }
}

// ============================================================================
// §2.4.0 main: CLI Encryption Flow
// ============================================================================
fn main() -> Result<()> {
    /* §2.4.1 parse args */
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();

    // New: detect and strip --thermo flag
    let mut use_thermo = false;
    if let Some(pos) = args.iter().position(|a| a == "--thermo") {
        use_thermo = true;
        args.remove(pos);
    }

    // support both: sarx_encrypt pw <password> <file>  OR  sarx_encrypt <file> [--password <pw>]
    let (infile, custom_pw) = if args.len() >= 3 && args[0] == "pw" {
        (args[2].clone(), Some(args[1].clone()))
    } else {
        let infile = args.get(0).cloned().context(
            "Usage: sarx_encrypt [--thermo] <input_file> [--password <pw>]  |  sarx_encrypt pw <password> [--thermo] <input_file>"
        )?;
        let custom_pw = if args.len() >= 3 && args[1] == "--password" { Some(args[2].clone()) } else { None };
        (infile, custom_pw)
    };

    /* §2.4.2 open input & size */
    let mut fin = File::open(&infile).context("open input")?;
    let size = fin.metadata()?.len() as usize;

    /* §2.4.3 password selection + TTY behavior */
    let password = if let Some(ref pw) = custom_pw {
        let cp_count = pw.chars().count();
        if cp_count < 30 || cp_count > 100 {
            anyhow::bail!("Password must be 30–100 Unicode codepoints (found {}).", cp_count);
        }
        pw.clone()
    } else {
        random_unicode_password(30, 100)
    };
    if custom_pw.is_none() {
        // Only print the password if we generated it
        if atty::is(atty::Stream::Stdout) {
            println!("✅ Encrypted {infile}\nPassword: {password}");
        } else {
            println!("{password}");
        }
    } else {
        println!("✅ Encrypted {infile}");
    }

    /* §2.4.4 timestamp + nonce12 */
    let timestamp_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?.as_nanos() as u64;
    let mut nonce12 = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce12);

    /* §2.4.5 salt32 = BLAKE3(timestamp||nonce) */
    let mut salt_in = [0u8; 20];
    salt_in[0..8].copy_from_slice(&u64_be(timestamp_ns));
    salt_in[8..20].copy_from_slice(&nonce12);
    let mut hh = Blake3::new(); hh.update(&salt_in);
    let mut salt32 = [0u8; 32]; hh.finalize_xof().fill(&mut salt32);

    /* §2.4.6 Argon2id params → OKM = k_stream_len + 32 */
    let pass_bytes = password.as_bytes().len();
    let k_stream_len = round_up_32(pass_bytes).max(32);
    let okm_len = k_stream_len + 32;
    let mut okm = vec![0u8; okm_len];
    {
        use argon2::{Argon2, Params, Algorithm, Version};
        let params = Params::new(1 << 17, 3, 1, Some(okm_len)).unwrap(); // 128 MiB, t=3, lanes=1
        let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        a2.hash_password_into(password.as_bytes(), &salt32, &mut okm)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    }

    // Optional thermodynamic hardening: only if user requested --thermo.
    if use_thermo {
        thermo_harden_okm(&mut okm);
    }

    /* §2.4.7 split OKM → k_stream || k_mac32 */
    let (k_stream, k_mac) = okm.split_at(k_stream_len);
    let mut k_mac32 = [0u8; 32]; k_mac32.copy_from_slice(&k_mac[..32]);

    /* §2.4.8 config from RAW password (timestamp-bound) */
    let cfg = generate_config_with_timestamp(&password, None, 0, timestamp_ns)?;

    /* §2.4.10 header (61 bytes) */
    let header = VaultHeader {
        salt32,
        timestamp_ns,
        nonce12,
        t_cost: 3,
        m_cost: 17, // log2(128 MiB)
        lanes: 1,
        kdf_id: if use_thermo { 3 } else { 2 }, // 2 = Argon2id, 3 = Argon2id+thermo
    };
    let header_raw = header.encode();   // call it raw for clarity

    /* §2.4.11 open output .vault → write header + reserve tag */
    let outname = format!("{infile}.vault");
    let mut fout = File::create(&outname).context("create output")?;
    fout.write_all(&header_raw)?;
    let tag_pos = fout.stream_position()?;
    fout.write_all(&[0u8; SARX_TAG_BYTES])?;

    // §2.4.12 Init MAC domain over header + len_le.
    let mut mac = blake3::Hasher::new_keyed(&k_mac32);
    mac.update(b"SARX-MAC-v1");
    mac.update(&header_raw);
    mac.update(&(size as u64).to_le_bytes());

    // §2.4.13 Streaming + parallel XOR (rayon), keystream per tile.
    // Use one buffer and encrypt in place to avoid an extra copy.
    let chunk = 16 * 1024 * 1024;
    let mut buf = vec![0u8; chunk];
    let mut abs_off: u64 = 0;

    loop {
        let n = fin.read(&mut buf)?;
        if n == 0 { break; }

        // ~2 MiB tiles usually land best on desktop CPUs
        let tile = (2 * 1024 * 1024).min(n.max(1));

        buf[..n]
            .par_chunks_mut(tile)
            .enumerate()
            .try_for_each(|(i, dst)| -> Result<()> {
                let start = abs_off + (i * tile) as u64;

                TLS_KS.with(|cell| -> Result<()> {
                    let mut ks = cell.borrow_mut();
                    if ks.len() < dst.len() { ks.resize(dst.len(), 0); }

                    // Postmix is disabled; pass None.
                    generate_stream(&cfg, None, start, dst.len(), &mut ks[..dst.len()])?;
                    xor_inplace(dst, &ks[..dst.len()]);
                    ks[..dst.len()].zeroize();
                    Ok(())
                })
            })?;

        mac.update(&buf[..n]);
        fout.write_all(&buf[..n])?;
        abs_off += n as u64;
    }

    /* §2.4.14 finalize tag and patch */
    let mut tag = [0u8; 32];
    mac.finalize_xof().fill(&mut tag);
    fout.seek(SeekFrom::Start(tag_pos))?;
    fout.write_all(&tag)?;

    /* §2.4.15 durability: flush + fsync, then delete plaintext */
    fout.flush()?;        // flush userspace buffers
    fout.sync_all()?;     // fsync file to disk
    drop(fout);           // close vault
    drop(fin);            // close plaintext
    std::fs::remove_file(&infile)
        .with_context(|| format!("failed to remove plaintext: {}", &infile))?;

    /* §2.4.16 hygiene: zeroize OKM */
    okm.zeroize();
    Ok(())
}
