//! §3.1.0 Overview — CLI: decrypt .vault
//! - Read 61B header, 32B tag
//! - Verify BLAKE3 keyed MAC first
//! - Rebuild config+postmix, stream XOR in parallel
//! - Strip ".vault" suffix if present for output
//!
//! /* =============================================================================
//!  * SARX — sarx_decrypt.rs — Program v3.0.0
//!  * Numbering: Program=3.0.0, Sections=§3.X.0, Subsections=§3.X.Y
//!  * Cross-reference these tags later when building the ToC.
//!  * =============================================================================
//!  */

// ============================================================================
// §3.2.0 Imports & Crate Uses
// ============================================================================
use anyhow::{Context, Result};
use subtle::ConstantTimeEq;
use rayon::prelude::*;
use zeroize::Zeroize;

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::cell::RefCell;

use sarx::{
    headers::{SARX_HEADER_BYTES, SARX_TAG_BYTES, VaultHeader},
    sarx::{generate_stream, generate_config_with_timestamp, thermo_harden_okm},
};

// ============================================================================
// §3.3.0 Primitives & TLS Cache
// Purpose: tiny helpers and thread-local keystream buffer.
// ============================================================================

/* §3.3.1 TLS_KS: thread-local keystream scratch */
thread_local! {
    static TLS_KS: RefCell<Vec<u8>> = RefCell::new(Vec::new());
}

/* §3.3.2 xor_bytes_into: dst = a XOR b */
#[inline]
fn xor_bytes_into(dst: &mut [u8], a: &[u8], b: &[u8]) {
    for i in 0..a.len() { dst[i] = a[i] ^ b[i]; }
}

// ============================================================================
// §3.4.0 Main Entry & Flow
// ============================================================================
fn main() -> Result<()> {
    // §3.4.1 Parse args & open input
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    // support both: sarx_decrypt <vault_file>  OR  sarx_decrypt pw <password> <vault_file>
    let (password_arg, infile) = if args.len() >= 3 && args[0] == "pw" {
        (Some(args[1].clone()), args[2].clone())
    } else {
        (None, args.get(0).cloned().context("Usage: sarx_decrypt <vault_file>  |  sarx_decrypt pw <password> <vault_file>")?)
    };
    let mut fin = File::open(&infile).context("open")?;

    // §3.4.2 Read & decode header
    let mut hdr = [0u8; SARX_HEADER_BYTES];
    fin.read_exact(&mut hdr)?;
    // grab both struct and raw 61 bytes
    let (header, header_raw) = VaultHeader::decode_with_raw(&hdr)?;

    // §3.4.3 Read tag
    let mut tag_file = [0u8; SARX_TAG_BYTES];
    fin.read_exact(&mut tag_file)?;

    // §3.4.4 Size checks & ciphertext extent
    let file_size = fin.metadata()?.len();
    if file_size < (SARX_HEADER_BYTES + SARX_TAG_BYTES) as u64 {
        anyhow::bail!("invalid vault");
    }
    let clen = (file_size as usize) - (SARX_HEADER_BYTES + SARX_TAG_BYTES);
    let ct_start = (SARX_HEADER_BYTES + SARX_TAG_BYTES) as u64;

    // §3.4.5 Password selection (CLI 'pw' or TTY prompt)
    let password = if let Some(p) = password_arg {
        let cp = p.chars().count();
        if cp < 30 || cp > 100 {
            anyhow::bail!("Password must be 30–100 Unicode codepoints (found {}).", cp);
        }
        p
    } else if atty::is(atty::Stream::Stdin) {
        rpassword::prompt_password("Password: ")?
    } else {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        s.trim_end_matches(&['\r','\n'][..]).to_string()
    };

    // §3.4.6 Derive k_stream/k_mac via Argon2id(+thermo) using header params
    if header.kdf_id != 2 && header.kdf_id != 3 {
        anyhow::bail!("kdf_id unsupported");
    }
    if !(1..=10).contains(&header.t_cost) { anyhow::bail!("t_cost out of range"); }
    if !(10..=24).contains(&header.m_cost) { anyhow::bail!("m_cost out of range"); }
    if !(1..=4).contains(&header.lanes) { anyhow::bail!("lanes out of range"); }

    let pass_bytes = password.as_bytes().len();
    let k_stream_len = ((pass_bytes + 31) & !31).max(32);
    let okm_len = k_stream_len + 32;
    let mut okm = vec![0u8; okm_len];
    {
        use argon2::{Argon2, Params, Algorithm, Version};
        let mem_kib: u32 = 1u32 << header.m_cost;
        let params = Params::new(mem_kib, header.t_cost.into(), header.lanes.into(), Some(okm_len)).unwrap();
        let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        a2.hash_password_into(password.as_bytes(), &header.salt32, &mut okm)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    }

    // If this vault was created with thermo-hard KDF, run the same hardening.
    if header.kdf_id == 3 {
        thermo_harden_okm(&mut okm);
    }

    let (k_stream, k_mac) = okm.split_at(k_stream_len);
    let mut k_mac32 = [0u8; 32]; k_mac32.copy_from_slice(&k_mac[..32]);

    // §3.4.7 Compute and verify keyed BLAKE3 MAC
    let mut mac = blake3::Hasher::new_keyed(&k_mac32);
    mac.update(b"SARX2DU-MAC-v1");
    // MAC the raw 61 bytes from disk
    mac.update(&header_raw);
    mac.update(&(clen as u64).to_le_bytes());

    fin.seek(SeekFrom::Start(ct_start))?;
    let chunk = 16 * 1024 * 1024;
    let mut ct_buf = vec![0u8; chunk];
    let mut remain = clen;
    while remain > 0 {
        let n = remain.min(chunk);
        fin.read_exact(&mut ct_buf[..n])?;
        mac.update(&ct_buf[..n]);
        remain -= n;
    }
    let mut tag_calc = [0u8; 32];
    mac.finalize_xof().fill(&mut tag_calc);
    if ConstantTimeEq::ct_eq(&tag_calc[..], &tag_file[..]).unwrap_u8() == 0 {
        // clearer wording: this is a keyed BLAKE3 MAC, not HMAC-SHA
        anyhow::bail!("MAC mismatch (wrong password or corrupted file)");
    }

    // §3.4.8 Rewind for decrypt pass
    fin.seek(SeekFrom::Start(ct_start))?;

    // §3.4.9 Build SARX config + postmix
    let cfg = generate_config_with_timestamp(&password, None, 0, header.timestamp_ns)?;
    let mut postmix = Vec::with_capacity(16 + k_stream_len + 12 + 8);
    postmix.extend_from_slice(b"SARX2DU-POST\0\0\0\0");
    postmix.extend_from_slice(k_stream);
    postmix.extend_from_slice(&header.nonce12);
    postmix.extend_from_slice(&header.timestamp_ns.to_be_bytes());

    // §3.4.10 Output filename (strip ".vault" if present)
    let outname = infile.strip_suffix(".vault").unwrap_or(&infile).to_string();
    let mut fout = File::create(&outname).context("create out")?;

    // §3.4.11 Streaming parallel decrypt
    let mut ct = vec![0u8; chunk];
    let mut pt = vec![0u8; chunk];
    let mut abs_off: u64 = 0;
    let mut left = clen;

    while left > 0 {
        let n = left.min(chunk);
        fin.read_exact(&mut ct[..n])?;

        let slice = (8 * 1024 * 1024).min(n.max(1));
        pt[..n].par_chunks_mut(slice)
            .zip(ct[..n].par_chunks(slice))
            .enumerate()
            .try_for_each(|(i, (dst, src))| -> Result<()> {
                let start = abs_off + (i * slice) as u64;

                TLS_KS.with(|cell| -> Result<()> {
                    let mut ks = cell.borrow_mut();
                    if ks.len() < src.len() { ks.resize(src.len(), 0); }

                    generate_stream(&cfg, Some(&postmix), start, src.len(), &mut ks[..src.len()])?;

                    xor_bytes_into(dst, src, &ks[..src.len()]);

                    use zeroize::Zeroize;
                    ks[..src.len()].zeroize();
                    Ok(())
                })
            })?;

        fout.write_all(&pt[..n])?;
        abs_off += n as u64;
        left -= n;
    }

    // §3.4.12 Durability: flush & fsync, then remove source .vault
    fout.flush()?;
    fout.sync_all()?;
    drop(fout);
    drop(fin);

    if infile.ends_with(".vault") {
        std::fs::remove_file(&infile)
            .with_context(|| format!("failed to remove source vault: {}", &infile))?;
    }

    // §3.4.13 Hygiene
    okm.zeroize();
    Ok(())
}
