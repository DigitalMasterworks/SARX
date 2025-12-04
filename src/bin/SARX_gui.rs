//! §7.1.0 Overview — SARX GUI (Rust, eframe/egui)
//! File: src/bin/sarx_gui.rs
//! Purpose: Desktop GUI for SARX encryption/decryption with USB sigilbook integration.
//!
//! /* =============================================================================
//!  * SARX — sarx_gui.rs — Program v7.0.0
//!  * Numbering: Program=7.0.0, Sections=§7.X.0, Subsections=§7.X.Y
//!  * Cross-reference these tags later when building the ToC.
//!  * =============================================================================
//!  */

// ============================================================================
// §7.2.0 Imports & Uses
// ============================================================================
use std::fs::File;
use std::fs;
use std::io::{BufRead, BufReader};
use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom, Write};
use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::mpsc::{self, Sender, Receiver};
use anyhow::{Context, Result};
use blake3::Hasher as Blake3;
use eframe::egui::{self, Button, TextEdit};
use egui::RichText;
use rand::RngCore;
use rayon::prelude::*;
use zeroize::Zeroize;
use percent_encoding::percent_decode_str;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use sarx::{
    headers::{SARX_HEADER_BYTES, SARX_TAG_BYTES, VaultHeader},
    sarx::{generate_config_with_timestamp, generate_stream, thermo_harden_okm},
};

// ============================================================================
// §7.3.0 USB Detection & Sigilbook Save, Helper Functions
// ============================================================================

thread_local! {
    static GUI_TLS_KS: RefCell<Vec<u8>> = RefCell::new(Vec::new());
}

fn usb_key_detected() -> bool {
    // same logic as python: look for VELVETKEY.info under /media/$USER or /run/media/$USER
    let user = whoami::username(); // add whoami = "1" to Cargo.toml if not present
    let bases = [format!("/media/{user}"), format!("/run/media/{user}")];
    for base in bases {
        if let Ok(rd) = std::fs::read_dir(&base) {
            for e in rd.flatten() {
                let p = e.path().join("VELVETKEY.info");
                if p.is_file() { return true; }
            }
        }
    }
    false
}

fn sigilbook_save(vault_path: &std::path::Path, password: &str) -> bool {
    let prog = sigilbook_prog();

    let mut child = match Command::new(&prog)
        .arg("save")
        .arg(vault_path)     // sigilbook save <vaultfile> -
        .arg("-")            // read password from stdin
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => { eprintln!("[sigilbook] spawn error: {e}"); return false; }
    };

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        // newline is fine; CLI trims \r\n
        let _ = stdin.write_all(password.as_bytes());
        let _ = stdin.write_all(b"\n");
    }
    match child.wait_with_output() {
        Ok(o) if o.status.success() => true,
        Ok(o) => { eprintln!("[sigilbook] save failed: {}", String::from_utf8_lossy(&o.stderr)); false }
        Err(e) => { eprintln!("[sigilbook] wait error: {e}"); false }
    }
}

fn sigilbook_get(vault_path: &std::path::Path) -> Option<String> {
    let prog = sigilbook_prog();

    let out = Command::new(&prog)
        .arg("get")
        .arg(vault_path)      // sigilbook get <vaultfile>
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .ok()?;

    if !out.status.success() {
        eprintln!(
            "[sigilbook] get failed: status={:?}, stderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() || s == "(not found)" { None } else { Some(s) }
}

fn sigilbook_prog() -> String {
    if let Ok(p) = std::env::var("SIGILBOOK_PROG") {
        return p;
    }
    let local = std::path::PathBuf::from("./target/release/sigilbook");
    if local.exists() {
        return local.to_string_lossy().into_owned();
    }
    "sigilbook".to_string()
}
// ---------------------------------------------------------------------------
// §7.3.4 sigilbook_get_async — async fetch from sigilbook and decrypt launcher
// ---------------------------------------------------------------------------
fn sigilbook_get_async(vault_path: std::path::PathBuf, tx: Sender<Event>) {
    let prog = sigilbook_prog();
    std::thread::spawn(move || {
        let out = Command::new(&prog)
            .arg("get").arg(&vault_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        match out {
            Ok(o) if o.status.success() => {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s.is_empty() || s == "(not found)" {
                    let _ = tx.send(Event::PromptPasswordFor { path: vault_path.clone() });
                } else {
                    let infile = vault_path.clone();
                    let tx2 = tx.clone();
                    std::thread::spawn(move || {
                        let res = decrypt_file(&infile, &s);
                        match res {
                            Ok(()) => {
                                let name = infile.file_name().and_then(|q| q.to_str()).unwrap_or_default().to_string();
                                let base = name.strip_suffix(".vault").unwrap_or(&name).to_string();
                                let out = infile.with_file_name(base);
                                let _ = tx2.send(Event::DecryptDone { out, _src_removed: true });
                            }
                            Err(e) => { let _ = tx2.send(Event::Error { message: e.to_string() }); }
                        }
                    });
                }
            }
            Ok(o) => {
                let _ = tx.send(Event::Error {
                    message: format!("sigilbook get failed: {:?}", o.status.code())
                });
            }
            Err(e) => {
                let _ = tx.send(Event::Error { message: format!("spawn get error: {e}") });
            }
        }
    });
}

// ---------------------------------------------------------------------------
// §7.3.5 list_mounted_drives — enumerate user-visible volumes for file panel
// ---------------------------------------------------------------------------
fn list_mounted_drives() -> Vec<PathBuf> {
    // Parse /proc/mounts and also scan /media/$USER and /run/media/$USER.
    // Keep unique, show only top-level mount points that look like real volumes.
    let mut set: BTreeSet<PathBuf> = BTreeSet::new();

    // /proc/mounts (fast)
    if let Ok(s) = fs::read_to_string("/proc/mounts") {
        for line in s.lines() {
            let parts: Vec<_> = line.split_whitespace().collect();
            if parts.len() < 3 { continue; }
            let _src = parts[0];            // /dev/sda1, etc
            let mpt = parts[1];             // mountpoint
            let fstype = parts[2];          // ext4, vfat, ntfs, exfat, fuseblk, etc.

            // Filter: likely “real” user volumes
            let is_fs = matches!(fstype,
                "ext4" | "ext3" | "ext2" | "xfs" | "btrfs" |
                "vfat" | "exfat" | "ntfs" | "fuseblk" |
                "hfsplus" | "apfs"
            );
            // Skip obvious virtual/special mounts
            let skip = mpt.starts_with("/proc")
                || mpt.starts_with("/sys")
                || mpt.starts_with("/dev")
                || mpt.starts_with("/run/user")
                || mpt == "/";

            if is_fs && !skip {
                set.insert(PathBuf::from(mpt));
            }
        }
    }

    // Also scan user media paths
    let user = whoami::username();
    for base in [format!("/media/{user}"), format!("/run/media/{user}")].into_iter() {
        if let Ok(rd) = fs::read_dir(&base) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() { set.insert(p); }
            }
        }
    }

    set.into_iter().collect()
}

// ---------------------------------------------------------------------------
// §7.3.6 load_gtk_bookmarks — read GTK bookmarks and decode file:// URIs
// ---------------------------------------------------------------------------
fn load_gtk_bookmarks() -> Vec<PathBuf> {
    // GTK bookmarks live in these files; lines like: file:///path/to/folder  Optional Label
    let mut paths: BTreeSet<PathBuf> = BTreeSet::new();
    let candidates = [
        dirs::config_dir().map(|p| p.join("gtk-3.0/bookmarks")),
        dirs::config_dir().map(|p| p.join("gtk-4.0/bookmarks")),
    ];

    for maybe_file in candidates {
        if let Some(file) = maybe_file {
            if let Ok(f) = fs::File::open(&file) {
                let reader = BufReader::new(f);
                for line in reader.lines().flatten() {
                    let line = line.trim();
                    if line.is_empty() { continue; }
                    let uri = line.split_whitespace().next().unwrap_or("");
                    if let Some(stripped) = uri.strip_prefix("file://") {
                        // robust decode of file:// URI → path
                        let decoded = percent_decode_str(stripped).decode_utf8_lossy().to_string();
                        let pb = PathBuf::from(decoded);
                        if pb.exists() { paths.insert(pb); }
                    }
                }
            }
        }
    }
    paths.into_iter().collect()
}

#[inline] fn u64_be(x: u64) -> [u8; 8] { x.to_be_bytes() }
#[inline] fn round_up_32(x: usize) -> usize { (x + 31) & !31 }

// ============================================================================
// §7.4.0 Events & Password Utility
// ============================================================================
#[derive(Debug)]
enum Event {
    EncryptDone { password: String, out: std::path::PathBuf, _src_removed: bool },
    DecryptDone { out: std::path::PathBuf, _src_removed: bool },
    BatchDone { statuses: Vec<(std::path::PathBuf, &'static str)>, csv: Option<std::path::PathBuf> },
    BatchDecryptDone { statuses: Vec<(std::path::PathBuf, &'static str)> },
    PromptPasswordFor { path: std::path::PathBuf },
    Error { message: String },
}

fn random_unicode_password(min_cps: usize, max_cps: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let target = rng.gen_range(min_cps..=max_cps);
    let mut s = String::new();
    let mut cps = 0usize;
    while cps < target {
        let cp = loop {
            let r1: u32 = rng.gen(); let r2: u32 = rng.gen();
            let v = (r1 ^ (r2 << 1)) % 0x110000;
            if !(0xD800..=0xDFFF).contains(&v) && v >= 0x20 { break v; }
        };
        if let Some(ch) = char::from_u32(cp) { s.push(ch); cps += 1; }
    }
    s
}

// ============================================================================
// §7.5.0 Core Encrypt/Decrypt
// ============================================================================
fn encrypt_file(infile: &PathBuf, user_password: Option<&str>, use_thermo: bool) -> Result<String> {
    let mut fin = File::open(infile).context("open input")?;
    let size = fin.metadata()?.len() as usize;

    // password selection
    let password = if let Some(pw) = user_password {
        let cps = pw.chars().count();
        if (30..=100).contains(&cps) {
            pw.to_string()
        } else {
            anyhow::bail!("Password must be 30–100 Unicode codepoints (got {cps}).");
        }
    } else {
        random_unicode_password(30, 100)
    };

    // ts + nonce
    let timestamp_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?.as_nanos() as u64;
    let mut nonce12 = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce12);

    // salt = blake3(ts||nonce)
    let mut salt_in = [0u8; 20];
    salt_in[..8].copy_from_slice(&u64_be(timestamp_ns));
    salt_in[8..].copy_from_slice(&nonce12);
    let mut hh = Blake3::new(); hh.update(&salt_in);
    let mut salt32 = [0u8; 32]; hh.finalize_xof().fill(&mut salt32);

    // Argon2id: OKM = k_stream_len + 32
    let pass_bytes = password.as_bytes().len();
    let k_stream_len = ((pass_bytes + 31) & !31).max(32);
    let okm_len = k_stream_len + 32;
    let mut okm = vec![0u8; okm_len];
    {
        use argon2::{Argon2, Params, Algorithm, Version};
        let params = Params::new(1 << 17, 3, 1, Some(okm_len)).unwrap(); // 128 MiB, t=3, lanes=1
        let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        a2.hash_password_into(password.as_bytes(), &salt32, &mut okm)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    }

    // Optional thermodynamic hardening for GUI (matches CLI --thermo)
    if use_thermo {
        thermo_harden_okm(&mut okm);
    }

    let (k_stream, k_mac) = okm.split_at(k_stream_len);
    let mut k_mac32 = [0u8; 32]; k_mac32.copy_from_slice(&k_mac[..32]);
    let mut k_mac32 = [0u8; 32]; k_mac32.copy_from_slice(&k_mac[..32]);

    // config
    let cfg = generate_config_with_timestamp(&password, None, 0, timestamp_ns)?;

    // postmix = label || k_stream || nonce || ts_be
    let mut postmix = Vec::with_capacity(16 + k_stream_len + 12 + 8);
    postmix.extend_from_slice(b"SARX2DU-POST\0\0\0\0");
    postmix.extend_from_slice(k_stream);
    postmix.extend_from_slice(&nonce12);
    postmix.extend_from_slice(&u64_be(timestamp_ns));

    // header
    let header = VaultHeader {
        salt32,
        timestamp_ns,
        nonce12,
        t_cost: 3,
        m_cost: 17,
        lanes: 1,
        kdf_id: if use_thermo { 3 } else { 2 }, // 2 = Argon2id, 3 = Argon2+thermo
    };
    let header_bytes = header.encode();

    // output name: "<file>.<ext>.vault"
    let outname = infile.with_file_name(format!(
        "{}.vault",
        infile.file_name().and_then(|s| s.to_str()).unwrap_or("output")
    ));
    let mut fout = File::create(&outname).context("create output")?;

    // header + reserve tag
    fout.write_all(&header_bytes)?;
    let tag_pos = fout.stream_position()?;
    fout.write_all(&[0u8; SARX_TAG_BYTES])?;

    // MAC init
    let mut mac = blake3::Hasher::new_keyed(&k_mac32);
    mac.update(b"SARX2DU-MAC-v1");
    mac.update(&header_bytes);
    mac.update(&(size as u64).to_le_bytes());

    // stream + parallel XOR
    let chunk = 16 * 1024 * 1024;
    let mut pt = vec![0u8; chunk];
    let mut ct = vec![0u8; chunk];
    let mut abs_off: u64 = 0;

    loop {
        let n = fin.read(&mut pt)?;
        if n == 0 { break; }
        let slice = (1 * 1024 * 1024).min(n.max(1));

        ct[..n].par_chunks_mut(slice)
            .zip(pt[..n].par_chunks(slice))
            .enumerate()
            .try_for_each(|(i, (dst, src))| -> Result<()> {
                let start = abs_off + (i * slice) as u64;

                GUI_TLS_KS.with(|cell| -> Result<()> {
                    let mut ks = cell.borrow_mut();
                    if ks.len() < src.len() { ks.resize(src.len(), 0); }
                    generate_stream(&cfg, Some(&postmix), start, src.len(), &mut ks[..src.len()])?;
                    for j in 0..src.len() { dst[j] = src[j] ^ ks[j]; }
                    use zeroize::Zeroize;
                    ks[..src.len()].zeroize();
                    Ok(())
                })
            })?;

        mac.update(&ct[..n]);
        fout.write_all(&ct[..n])?;
        abs_off += n as u64;
    }

    // finalize tag
    let mut tag = [0u8; 32];
    mac.finalize_xof().fill(&mut tag);
    fout.seek(SeekFrom::Start(tag_pos))?;
    fout.write_all(&tag)?;

    // swap: delete plaintext after success
    fout.sync_all()?;
    drop(fout);
    drop(fin);
    std::fs::remove_file(infile)
        .with_context(|| format!("failed to remove plaintext: {}", infile.display()))?;

    okm.zeroize();
    Ok(password)
}

fn decrypt_file(infile: &PathBuf, password: &str) -> Result<()> {
    let mut fin = File::open(infile).context("open")?;
    let mut hdr = [0u8; SARX_HEADER_BYTES]; fin.read_exact(&mut hdr)?;
    let header = VaultHeader::decode(&hdr)?;
    let mut tag_file = [0u8; SARX_TAG_BYTES]; fin.read_exact(&mut tag_file)?;

    let file_size = fin.metadata()?.len();
    if file_size < (SARX_HEADER_BYTES + SARX_TAG_BYTES) as u64 {
        anyhow::bail!("invalid vault");
    }
    let clen = (file_size as usize) - (SARX_HEADER_BYTES + SARX_TAG_BYTES);
    let ct_start = (SARX_HEADER_BYTES + SARX_TAG_BYTES) as u64;

    // KDF checks + derive
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

    // Only thermo-harden OKM when the vault was created in thermo mode
    if header.kdf_id == 3 {
        thermo_harden_okm(&mut okm);
    }

    let (k_stream, k_mac) = okm.split_at(k_stream_len);
    let mut k_mac32 = [0u8; 32]; k_mac32.copy_from_slice(&k_mac[..32]);

    // MAC verify first
    let mut mac = blake3::Hasher::new_keyed(&k_mac32);
    mac.update(b"SARX2DU-MAC-v1");
    mac.update(&hdr);
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
    if subtle::ConstantTimeEq::ct_eq(&tag_calc[..], &tag_file[..]).unwrap_u8() == 0 {
        anyhow::bail!("MAC mismatch (wrong password or corrupted file)");
    }

    // rewind and decrypt
    fin.seek(SeekFrom::Start(ct_start))?;
    let cfg = generate_config_with_timestamp(&password, None, 0, header.timestamp_ns)?;
    let mut postmix = Vec::with_capacity(16 + k_stream_len + 12 + 8);
    postmix.extend_from_slice(b"SARX2DU-POST\0\0\0\0");
    postmix.extend_from_slice(k_stream);
    postmix.extend_from_slice(&header.nonce12);
    postmix.extend_from_slice(&header.timestamp_ns.to_be_bytes());

    let outname = infile
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.strip_suffix(".vault").unwrap_or(s).to_string())
        .unwrap_or_else(|| "output.bin".to_string());
    let outpath = infile.with_file_name(outname);
    let mut fout = File::create(&outpath).context("create out")?;

    let mut ct = vec![0u8; chunk];
    let mut pt = vec![0u8; chunk];
    let mut abs_off: u64 = 0;
    let mut left = clen;

    while left > 0 {
        let n = left.min(chunk);
        fin.read_exact(&mut ct[..n])?;
        let slice = (1 * 1024 * 1024).min(n.max(1));

        pt[..n].par_chunks_mut(slice)
            .zip(ct[..n].par_chunks(slice))
            .enumerate()
            .try_for_each(|(i, (dst, src))| -> Result<()> {
                let start = abs_off + (i * slice) as u64;

                GUI_TLS_KS.with(|cell| -> Result<()> {
                    let mut ks = cell.borrow_mut();
                    if ks.len() < src.len() { ks.resize(src.len(), 0); }
                    generate_stream(&cfg, Some(&postmix), start, src.len(), &mut ks[..src.len()])?;
                    for j in 0..src.len() { dst[j] = src[j] ^ ks[j]; }
                    use zeroize::Zeroize;
                    ks[..src.len()].zeroize();
                    Ok(())
                })
            })?; // close try_for_each and propagate errors

        fout.write_all(&pt[..n])?;
        abs_off += n as u64;
        left -= n;
    }

    // swap: delete source vault
    fout.sync_all()?;
    drop(fout);
    drop(fin);
    if infile
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.ends_with(".vault"))
        .unwrap_or(false)
    {
        std::fs::remove_file(infile)
            .with_context(|| format!("failed to remove source vault: {}", infile.display()))?;
    }

    okm.zeroize();
    Ok(())
}

// ============================================================================
// §7.6.0 GUI State
// ============================================================================
struct App {
    in_path: Option<PathBuf>,
    status: String,
    last_password: String,
    show_pw_prompt: bool,
    pw_input: String,
    busy: bool,
    tx: Sender<Event>,
    rx: Receiver<Event>,
    usb_detected: bool,
    save_to_key: bool,
    use_user_pw: bool,
    show_enc_pw_prompt: bool,
    enc_pw_input: String,
    last_poll: Instant,
    poll_interval: Duration,
    current_dir: PathBuf,
    filter: String,
    selected_paths: BTreeSet<std::path::PathBuf>,
    batch_status: Vec<(std::path::PathBuf, &'static str)>,
    show_hint: Option<String>,
    hint_ts: Instant,
    mounts: Vec<PathBuf>,
    bookmarks: Vec<PathBuf>,
    last_anchor: Option<PathBuf>,
    use_thermo_kdf: bool,
}

impl Default for App {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            in_path: None,
            status: format!("Pick a file, then Encrypt or Decrypt. Using sigilbook: {}", sigilbook_prog()),
            last_password: String::new(),
            show_pw_prompt: false,
            pw_input: String::new(),
            busy: false,
            tx, rx,
            usb_detected: usb_key_detected(),
            save_to_key: true,
            use_user_pw: false,
            show_enc_pw_prompt: false,
            enc_pw_input: String::new(),
            last_poll: Instant::now(),
            poll_interval: Duration::from_millis(1000),
            current_dir: PathBuf::from("/"),
            filter: String::new(),
            selected_paths: BTreeSet::new(),
            batch_status: Vec::new(),
            show_hint: None,
            hint_ts: Instant::now(),
            mounts: list_mounted_drives(),
            bookmarks: load_gtk_bookmarks(),
            last_anchor: None,
            use_thermo_kdf: false,   // ← add this
        }
    }
}

// ============================================================================
// §7.7.0 GUI Implementation (eframe::App)
// ============================================================================
impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.last_poll.elapsed() >= self.poll_interval {
            self.usb_detected = usb_key_detected();
            self.last_poll = Instant::now();
        }
        ctx.request_repaint_after(Duration::from_millis(200));

        egui::CentralPanel::default().show(ctx, |ui| {
            let available = ui.available_size();
            let half_width = available.x / 2.0;

            ui.horizontal(|ui| {
                // ================= LEFT SIDE (controls) =================
                ui.allocate_ui_with_layout(
                    egui::Vec2::new(half_width, available.y),
                    egui::Layout::top_down(egui::Align::Center),
                    |ui| {
                        // selection comes from the built-in file manager (right)
                        match self.selected_paths.len() {
                            0 => ui.label(RichText::new("No file selected (pick on the right)").italics()),
                            1 => {
                                let p = self.selected_paths.iter().next().unwrap();
                                ui.label(RichText::new(p.display().to_string()).monospace())
                            }
                            n => ui.label(RichText::new(format!("{n} files selected")).monospace()),
                        };

                        ui.add_space(8.0);

                        ui.horizontal(|ui| {
                            let label = if self.usb_detected {
                                "USB Key: Detected ✅"
                            } else {
                                "USB Key: Not Detected ⛔"
                            };
                            ui.label(RichText::new(label).monospace());
                            ui.add_space(12.0);
                            ui.add_enabled(
                                self.usb_detected,
                                egui::Checkbox::new(&mut self.save_to_key, "Save password to key"),
                            );
                            ui.add_space(12.0);
                            ui.checkbox(&mut self.use_user_pw, "User provided password?");
                            if self.use_user_pw && self.enc_pw_input.is_empty() {
                                ui.add_space(8.0);
                                if ui.button("Set password…").clicked() {
                                    self.show_enc_pw_prompt = true;
                                }
                            }
                            ui.add_space(12.0);
                            ui.checkbox(&mut self.use_thermo_kdf, "Thermo KDF (slow, hardened)");
                        });
                        
                        if let Some(h) = &self.show_hint {
                            if self.hint_ts.elapsed() < Duration::from_secs(4) {
                                ui.colored_label(egui::Color32::YELLOW, h);
                            } else {
                                self.show_hint = None;
                            }
                        }

                        // Encrypt / Decrypt buttons
                        let enc = ui.add_sized(
                            [ui.available_width(), 56.0],
                            Button::new(RichText::new("🔐 ENCRYPT").size(22.0)),
                        );
                        let dec = ui.add_sized(
                            [ui.available_width(), 56.0],
                            Button::new(RichText::new("🔓 DECRYPT").size(22.0)),
                        );

                        // ENCRYPT click
                        if enc.clicked() && !self.busy {
                            let files: Vec<std::path::PathBuf> = self.selected_paths.iter().cloned().collect();
                            if files.is_empty() {
                                self.status = "Select at least one file.".into();
                            } else if files.len() == 1 {
                                // === SINGLE-FILE ENCRYPT ===
                                let infile = files[0].clone();
                                self.busy = true;
                                self.status = "Encrypting…".into();
                                let tx = self.tx.clone();
                                let user_pw_opt = if self.use_user_pw { Some(self.enc_pw_input.clone()) } else { None };
                                let use_thermo = self.use_thermo_kdf;
                                std::thread::spawn(move || {
                                    let res = encrypt_file(&infile, user_pw_opt.as_deref(), use_thermo);
                                    match res {
                                        Ok(pass) => {
                                            let out = infile.with_file_name(format!(
                                                "{}.vault",
                                                infile.file_name().and_then(|s| s.to_str()).unwrap_or("output")
                                            ));
                                            let _ = tx.send(Event::EncryptDone { password: pass, out, _src_removed: true });
                                        }
                                        Err(e) => {
                                            let _ = tx.send(Event::Error { message: e.to_string() });
                                        }
                                    }
                                });
                            } else {
                                // === BATCH ENCRYPT (USB required) ===
                                if !self.usb_detected {
                                    self.show_hint = Some("Batch mode requires your USB key. You can still encrypt one file at a time.".to_string());
                                    self.hint_ts = Instant::now();
                                } else {
                                    self.busy = true;
                                    self.status = "Batch encrypting…".into();
                                    self.last_password.clear();
                                    self.batch_status.clear();

                                    let tx = self.tx.clone();
                                    let use_thermo = self.use_thermo_kdf; // 👈 capture the flag by value
                                    std::thread::spawn(move || {
                                        let mut statuses: Vec<(std::path::PathBuf, &'static str)> = Vec::new();
                                        let mut rows_with_passwords: Vec<(std::path::PathBuf, String)> = Vec::new();

                                        for infile in files {
                                            if !usb_key_detected() {
                                                let _ = tx.send(Event::Error { message: "USB missing — reinsert to continue or cancel.".into() });
                                                while !usb_key_detected() {
                                                    std::thread::sleep(std::time::Duration::from_millis(500));
                                                }
                                            }

                                            match encrypt_file(&infile, None, use_thermo) {
                                                Ok(pass) => {
                                                    let out_vault = infile.with_file_name(format!(
                                                        "{}.vault",
                                                        infile.file_name().and_then(|s| s.to_str()).unwrap_or("output")
                                                    ));
                                                    rows_with_passwords.push((out_vault.clone(), pass));
                                                    statuses.push((infile.clone(), "OK"));
                                                }
                                                Err(_) => {
                                                    statuses.push((infile.clone(), "ERR"));
                                                }
                                            }
                                        }

                                        // [{"path":".../file.vault","password":"..."}]
                                        #[derive(serde::Serialize)]
                                        struct Row { path: String, password: String }
                                        let rows: Vec<Row> = rows_with_passwords.iter()
                                            .map(|(p, w)| Row {
                                                path: p.to_string_lossy().into_owned(),
                                                password: w.clone(),
                                            })
                                            .collect();

                                        // 1) Save each vault/password into the sigilbook DB
                                        for (out_vault, pass) in &rows_with_passwords {
                                            let prog = sigilbook_prog();
                                            let abs_out = std::fs::canonicalize(out_vault).unwrap_or(out_vault.clone());
                                            let child = std::process::Command::new(&prog)
                                                .arg("save")
                                                .arg(&abs_out)
                                                .arg("-")
                                                .stdin(std::process::Stdio::piped())
                                                .stdout(std::process::Stdio::null())
                                                .stderr(std::process::Stdio::piped())
                                                .spawn();

                                            if let Ok(mut ch) = child {
                                                if let Some(mut stdin) = ch.stdin.take() {
                                                    use std::io::Write;
                                                    let _ = stdin.write_all(pass.as_bytes());
                                                    let _ = stdin.write_all(b"\n");
                                                }
                                                match ch.wait_with_output() {
                                                    Ok(o) if o.status.success() => {}
                                                    Ok(o) => eprintln!("[batch] sigilbook save failed: {}", String::from_utf8_lossy(&o.stderr)),
                                                    Err(e) => eprintln!("[batch] spawn/save error: {e}"),
                                                }
                                            }
                                        }

                                        // (security) plaintext password export disabled.
                                        // Do NOT write any CSV/JSON containing passwords to the USB.
                                        let _ = tx.send(Event::BatchDone { statuses, csv: None });
                                    });
                                }
                            }
                        }

                        // DECRYPT click (single or batch)
                        if dec.clicked() && !self.busy {
                            let files: Vec<std::path::PathBuf> = self.selected_paths.iter().cloned().collect();
                            if files.is_empty() {
                                self.status = "Select at least one .vault file to decrypt.".into();
                            } else if files.len() == 1 {
                                let infile = files[0].clone();
                                if self.usb_detected {
                                    if let Some(pw) = sigilbook_get(&infile) {
                                        self.busy = true;
                                        self.status = "Decrypting…".into();
                                        let tx = self.tx.clone();
                                        std::thread::spawn(move || {
                                            let res = decrypt_file(&infile, &pw);
                                            match res {
                                                Ok(()) => {
                                                    let name = infile.file_name().and_then(|s| s.to_str()).unwrap_or_default().to_string();
                                                    let base = name.strip_suffix(".vault").unwrap_or(&name).to_string();
                                                    let out = infile.with_file_name(base);
                                                    let _ = tx.send(Event::DecryptDone { out, _src_removed: true });
                                                }
                                                Err(e) => { let _ = tx.send(Event::Error { message: e.to_string() }); }
                                            }
                                        });
                                    } else {
                                        self.busy = true;
                                        self.status = "Fetching password from key…".into();
                                        sigilbook_get_async(infile, self.tx.clone());
                                    }
                                } else {
                                    self.pw_input.clear();
                                    self.show_pw_prompt = true;
                                }
                            } else {
                                if !self.usb_detected {
                                    self.show_hint = Some("Batch decrypt requires your USB key. You can still decrypt one file at a time.".to_string());
                                    self.hint_ts = Instant::now();
                                } else {
                                    self.busy = true;
                                    self.status = "Batch decrypting…".into();
                                    self.batch_status.clear();
                                    let tx = self.tx.clone();
                                    std::thread::spawn(move || {
                                        let mut statuses: Vec<(std::path::PathBuf, &'static str)> = Vec::new();
                                        for infile in files {
                                            if !usb_key_detected() {
                                                statuses.push((infile.clone(), "USB?"));
                                                continue;
                                            }
                                            match sigilbook_get(&infile) {
                                                Some(pw) => {
                                                    match decrypt_file(&infile, &pw) {
                                                        Ok(()) => statuses.push((infile.clone(), "OK")),
                                                        Err(_) => statuses.push((infile.clone(), "ERR")),
                                                    }
                                                }
                                                None => {
                                                    statuses.push((infile.clone(), "MISS"));
                                                }
                                            }
                                        }
                                        let _ = tx.send(Event::BatchDecryptDone { statuses });
                                    });
                                }
                            }
                        }

                        // show last generated password (after single-file encrypt)
                        if !self.last_password.is_empty() {
                            ui.add_space(10.0);
                            ui.label("Generated password:");
                            ui.add_sized(
                                [ui.available_width(), 36.0],
                                TextEdit::singleline(&mut self.last_password),
                            );
                        }

                        // batch results table (no passwords)
                        if !self.batch_status.is_empty() {
                            ui.add_space(8.0);
                            ui.separator();
                            ui.label("Batch results:");
                            for (p, s) in &self.batch_status {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(p.display().to_string()).monospace());
                                    let col = if *s == "OK" { egui::Color32::GREEN } else { egui::Color32::RED };
                                    ui.colored_label(col, *s);
                                });
                            }
                        }

                        ui.add_space(10.0);
                        ui.label(RichText::new(&self.status).monospace());
                    },
                );
// ---------------------------------------------------------------------------
// §7.7.8 File manager panel (mounts, bookmarks, search, dir listing)
// ---------------------------------------------------------------------------
                // ================= RIGHT SIDE (file manager) =================
                ui.allocate_ui_with_layout(
                    egui::Vec2::new(half_width, available.y),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.heading("📂 File Manager");
                        ui.add_space(8.0);

                        // toolbar: current path + Up / Root / Home
                        ui.horizontal_wrapped(|ui| {
                            // Root
                            if ui.button("⤴ /").clicked() {
                                self.current_dir = PathBuf::from("/");
                                self.selected_paths.clear();
                            }

                            // Mounts (volumes)
                            if !self.mounts.is_empty() {
                                ui.label("• Mounts:");
                                for m in &self.mounts {
                                    let name: String = m.file_name()
                                        .and_then(|s| s.to_str())
                                        .map(|s| s.to_owned())
                                        .unwrap_or_else(|| m.to_string_lossy().into_owned());
                                    if ui.button(format!("🖴 {}", name)).clicked() {
                                        self.current_dir = m.clone();
                                        self.selected_paths.clear();
                                    }
                                }
                            }

                            // Bookmarks
                            if !self.bookmarks.is_empty() {
                                ui.label("• Bookmarks:");
                                for b in &self.bookmarks {
                                    let name: String = b.file_name()
                                        .and_then(|s| s.to_str())
                                        .map(|s| s.to_owned())
                                        .unwrap_or_else(|| b.to_string_lossy().into_owned());
                                    if ui.button(format!("📌 {}", name)).clicked() {
                                        self.current_dir = b.clone();
                                        self.selected_paths.clear();
                                    }
                                }
                            }
                        });
                        ui.add_space(6.0);

                        // persistent search
                        ui.add(
                            TextEdit::singleline(&mut self.filter)
                                .hint_text("Search… (filters by path substring)")
                                .desired_width(ui.available_width()),
                        );
                        ui.add_space(6.0);

                        // read and sort entries (dirs first, then files, alphanumeric)
                        let mut entries: Vec<PathBuf> = match fs::read_dir(&self.current_dir) {
                            Ok(rd) => rd.filter_map(|e| e.ok().map(|e| e.path())).collect(),
                            Err(e) => {
                                ui.label(RichText::new(format!("(cannot read dir: {e})")).italics());
                                Vec::new()
                            }
                        };

                        entries.sort_by(|a, b| {
                            let ad = a.is_dir();
                            let bd = b.is_dir();
                            match bd.cmp(&ad) {                // dirs first
                                std::cmp::Ordering::Equal => {
                                    let an = a.file_name().and_then(|s| s.to_str()).unwrap_or("").to_ascii_lowercase();
                                    let bn = b.file_name().and_then(|s| s.to_str()).unwrap_or("").to_ascii_lowercase();
                                    an.cmp(&bn)
                                }
                                other => other,
                            }
                        });

                        // keep a stable clone for selection math and rendering by reference
                        let entries_all: Vec<PathBuf> = entries.clone();

                        // Special ".." entry (go up) if not root
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            if self.current_dir.parent().is_some() {
                                let resp = ui.selectable_label(false, "📁 ..");
                                if resp.clicked() {
                                    if let Some(p) = self.current_dir.parent() {
                                        self.current_dir = p.to_path_buf();
                                        self.selected_paths.clear();
                                    }
                                }
                            }

                            for path_ref in entries_all.iter() {
                                let path: PathBuf = path_ref.clone();

                                // search filter
                                let pstr = path.display().to_string();
                                if !self.filter.is_empty() && !pstr.contains(&self.filter) {
                                    continue;
                                }

                                if path.is_dir() {
                                    // click -> enter dir
                                    let resp = ui.selectable_label(false, format!("📁 {}", pstr));
                                    if resp.clicked() || resp.double_clicked() {
                                        self.current_dir = path.clone();
                                        self.selected_paths.clear();
                                    }
                                } else {
                                    // click -> select file; double click -> quick decrypt
                                    let selected = self.selected_paths.contains(&path);
                                    let resp = ui.selectable_label(selected, format!("📄 {}", pstr));
                                    if resp.clicked() {
                                        let allow_multi = self.usb_detected;
                                        let modifiers = ui.input(|i| i.modifiers.clone());

                                        if allow_multi && modifiers.shift {
                                            if let Some(anchor) = self.last_anchor.clone() {
                                                let mut all_entries: Vec<PathBuf> = entries_all.clone();
                                                all_entries.sort();
                                                if let (Some(ai), Some(ci)) =
                                                    (all_entries.iter().position(|p| *p == anchor), all_entries.iter().position(|p| *p == path))
                                                {
                                                    let (lo, hi) = if ai <= ci { (ai, ci) } else { (ci, ai) };
                                                    for p in &all_entries[lo..=hi] {
                                                        self.selected_paths.insert(p.clone());
                                                    }
                                                }
                                            }
                                            self.last_anchor = Some(path.clone());
                                        } else if allow_multi && (modifiers.command || modifiers.ctrl) {
                                            if self.selected_paths.contains(&path) {
                                                self.selected_paths.remove(&path);
                                            } else {
                                                self.selected_paths.insert(path.clone());
                                            }
                                            self.last_anchor = Some(path.clone());
                                        } else {
                                            self.selected_paths.clear();
                                            self.selected_paths.insert(path.clone());
                                            self.last_anchor = Some(path.clone());
                                        }

                                        if !allow_multi && self.selected_paths.len() > 1 {
                                            let keep = path.clone();
                                            self.selected_paths.clear();
                                            self.selected_paths.insert(keep);
                                            self.show_hint = Some("Batch mode requires your USB key. You can still encrypt one file at a time.".to_string());
                                            self.hint_ts = Instant::now();
                                        }
                                        self.status = "Ready.".into();
                                    }
                                    if resp.double_clicked() && !self.busy {
                                        if self.usb_detected {
                                            self.busy = true;
                                            self.status = "Fetching password from key…".into();
                                            sigilbook_get_async(path.clone(), self.tx.clone());
                                        } else {
                                            self.pw_input.clear();
                                            self.show_pw_prompt = true;
                                        }
                                    }
                                }
                            }
                        });
                    },
                );
            });
        });

        // password prompt window (DECRYPT)
        if self.show_pw_prompt {
            egui::Window::new("Enter password")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Password used during encryption:");
                    let _ = ui.add(
                        egui::TextEdit::singleline(&mut self.pw_input)
                            .password(true)
                            .desired_width(320.0),
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.show_pw_prompt = false;
                        }
                        if ui.button("Decrypt").clicked() && !self.busy {
                            self.show_pw_prompt = false;
                            if let Some(infile) = self.selected_paths.iter().next().cloned() {
                                self.busy = true;
                                self.status = "Decrypting…".into();
                                let pw = self.pw_input.clone();
                                let tx = self.tx.clone();
                                std::thread::spawn(move || {
                                    let res = decrypt_file(&infile, &pw);
                                    match res {
                                        Ok(()) => {
                                            let name = infile
                                                .file_name()
                                                .and_then(|s| s.to_str())
                                                .unwrap_or_default()
                                                .to_string();
                                            let base =
                                                name.strip_suffix(".vault").unwrap_or(&name).to_string();
                                            let out = infile.with_file_name(base);
                                            let _ = tx.send(Event::DecryptDone { out, _src_removed: true });
                                        }
                                        Err(e) => {
                                            let _ = tx.send(Event::Error { message: e.to_string() });
                                        }
                                    }
                                });
                            }
                        }
                    });
                });
        }

        // password popup (ENCRYPT)
        if self.show_enc_pw_prompt {
            egui::Window::new("Enter password for encryption")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Password must be 30–100 Unicode codepoints.");
                    let _ = ui.add(
                        egui::TextEdit::singleline(&mut self.enc_pw_input)
                            .password(true)
                            .desired_width(320.0),
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.show_enc_pw_prompt = false;
                            self.use_user_pw = false;
                            self.enc_pw_input.clear();
                        }
                        if ui.button("Use this password").clicked() {
                            let cps = self.enc_pw_input.chars().count();
                            if (30..=100).contains(&cps) {
                                self.show_enc_pw_prompt = false;
                                self.status = "Password set for next encrypt.".into();
                            } else {
                                self.status = format!("Password must be 30–100 codepoints (got {cps}).");
                            }
                        }
                    });
                });
        }

        // handle background events
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                Event::EncryptDone { password, out, _src_removed: _ } => {
                    self.last_password = password.clone();
                    self.status = format!("✅ Encrypted → {}", out.display());
                    if self.save_to_key && self.usb_detected {
                        self.status = format!("{}  • saving password to USB…", self.status);
                        let abs_out = std::fs::canonicalize(&out).unwrap_or(out.clone());
                        let ok = sigilbook_save(&abs_out, &password);
                        if ok {
                            if let Some(_) = sigilbook_get(&abs_out) {
                                self.status = format!("{}  • saved ✅ (retrievable from DB)", self.status);
                            } else {
                                self.status = format!("{}  • saved ⚠ but not retrievable from DB", self.status);
                            }
                        } else {
                            self.status = format!("{}  • save failed ❌ (see log)", self.status);
                        }
                    }
                    eprintln!("[DEBUG] save_to_key={} usb_detected={} out={} status={}",
                              self.save_to_key, self.usb_detected, out.display(), self.status);
                    self.busy = false;
                }
                Event::DecryptDone { out, _src_removed: _ } => {
                    self.status = format!("✅ Decrypted → {}", out.display());
                    self.busy = false;
                }
                Event::BatchDone { statuses, csv } => {
                    self.batch_status = statuses;
                    if let Some(p) = csv {
                        self.status = format!("Batch complete. Passwords saved to: {}", p.display());
                    } else {
                        self.status = "Batch complete.".into();
                    }
                    self.busy = false;
                }
                Event::BatchDecryptDone { statuses } => {
                    self.batch_status = statuses;
                    self.status = "Batch decrypt complete.".into();
                    self.busy = false;
                }
                Event::PromptPasswordFor { path } => {
                    self.pw_input.clear();
                    self.show_pw_prompt = true;
                    self.status = format!("⚠ Password not found on USB for this vault:\n{}\nEnter the password used during encryption.", path.display());
                    eprintln!("[WARN] USB DB lookup miss for {}", path.display());
                    self.busy = false;
                }
                Event::Error { message } => {
                    self.status = format!("❌ {message}");
                    self.busy = false;
                }
            }
        }

        // busy polling (unchanged)
        if self.busy {
            if let Some(kind) = ctx.data(|d| d.get_temp::<&'static str>(egui::Id::new("job_kind"))) {
                if let Some(path) = ctx.data(|d| d.get_temp::<PathBuf>(egui::Id::new("job_path"))) {
                    if kind == "encrypt" {
                        let out = path.with_file_name(format!(
                            "{}.vault",
                            path.file_name().and_then(|s| s.to_str()).unwrap_or("output")
                        ));
                        if out.exists() && !path.exists() {
                            // placeholder
                        }
                    } else if kind == "decrypt" {
                        let name =
                            path.file_name().and_then(|s| s.to_str()).unwrap_or_default().to_string();
                        let base = name.strip_suffix(".vault").unwrap_or(&name).to_string();
                        let out = path.with_file_name(base);
                        if out.exists() && !path.exists() {
                            self.status = "✅ Decrypted".into();
                            self.busy = false;
                            ctx.data_mut(|d| {
                                d.remove::<&'static str>(egui::Id::new("job_kind"));
                                d.remove::<PathBuf>(egui::Id::new("job_path"));
                                d.remove::<String>(egui::Id::new("job_pw"));
                            });
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// §7.8.0 Main
// ============================================================================
fn main() -> eframe::Result<()> {
    let mut opts = eframe::NativeOptions::default();
    opts.viewport.inner_size = Some(egui::Vec2 { x: 460.0, y: 260.0 });
    eframe::run_native("SARX", opts, Box::new(|_cc| Box::<App>::default()))
}
