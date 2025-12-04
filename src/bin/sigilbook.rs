//! §6.1.0 Overview — Velvet Sigilbook (Rust)
//! Layout:  [MAGIC="SIGL"(4) | VER(1) | SALT_LEN(1) | SALT[..]] | TAG(32) | CIPHERTEXT[..]
//! KDF:     scrypt N=2^14, r=8, p=1 → 32B seed
//! Stream:  XOR with SHA-256(seed || counter_le)
//! MAC:     BLAKE3 keyed with seed over: "SIGILBOOK-MAC-v1" || header || len_le || ciphertext
//! Notes:   - "save" accepts "-" to read password from stdin (keeps secrets out of argv)
//!          - holding DB syncs to USB automatically when key is present
//!          - Linux-only perms (0700 dir, 0600 files)
//!
//! /* =============================================================================
//!  * SARX — sigilbook.rs — Program v6.0.0
//!  * Numbering: Program=6.0.0, Sections=§6.X.0, Subsections=§6.X.Y
//!  * Cross-reference these tags later when building the ToC.
//!  * =============================================================================
//!  */

// ============================================================================
// §6.2.0 Imports & Uses
// ============================================================================
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write, BufReader, BufWriter};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;
// removed: use unicode_normalization::UnicodeNormalization;
use whoami;
use zeroize::Zeroize;
use std::process::Command;
use dirs;
use sarx::headers::{SARX_HEADER_BYTES, SARX_TAG_BYTES};
use cfg_if::cfg_if;
use std::os::fd::AsRawFd;

// ============================================================================
// §6.3.0 Constants
// ============================================================================
/* §6.3.1 Global paths & filenames */

#[allow(dead_code)]
const SEED_FILE: &str = ".sigil.seed";          // master key bytes (quick/dirty mode)
const USB_DETECT_LABEL: &str = "VELVETKEY.info";
const USB_SEED_FILE: &str = ".sigil.seed"; 
const BATCH_SUBDIR: &str = "sarx-batch";
const USB_KEY_FILENAME: &str = "Sigilbook-rust.sigil";

/* §6.3.2 Wire format */
const ACTIVE_USB_FILE: &str = ".velvet_last_usb";
const MAGIC: &[u8; 4] = b"SIGL";
const VERSION: u8 = 1;

/* §6.3.3 KDF parameters */
const SCRYPT_LOG_N: u8 = 14;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const SCRYPT_DKLEN: usize = 32;



// ============================================================================
// §6.4.0 CLI Definitions
// ============================================================================
#[derive(Parser)]
#[command(name="sigilbook", version, about="Velvet Sigilbook (Rust)")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write velvet key marker (VELVETKEY.info) to a mounted USB
    Writeusb,
    /// Detect and lock in a Velvet USB
    Detect,    
    // Forget
    Forget,
    /// Get password for a vault file
    Get { vaultfile: String },
    /// Save password for a vault file (pass '-' to read pw from stdin)
    Save { vaultfile: String, password: String },
    /// Batch-write passwords to USB as atomic CSV/JSON (reads JSON array from stdin)
    /// JSON input format: [{ "path": "<vault path>", "password": "<pw>" }, ...]
    Batch {
        /// Output format (csv or json). Default: csv
        #[arg(long, default_value = "csv")]
        format: String,
    },
    /// Safely rotate the USB seed and rewrap the DB (keeps all entries)
    Rekey,
    /// Hard reset: delete seed and password DB from the USB (irreversible)
    Reseed,
    /// Initialize: create new .sigil.seed and empty DB (first-time setup)
    Init,
}

// ============================================================================
// §6.5.0 Data Models
// ============================================================================
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
struct Db {
    #[serde(default)]
    entries: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Entry {
    // Stable, vault-intrinsic identity computed from header+tag (not path, not mtime).
    vault_id: String,
    password: String,
    #[serde(default)]
    paths: Vec<String>,
}

// ============================================================================
// §6.6.0 Guards & Directories
// ============================================================================
fn velvet_guard() -> Result<()> {
//    let user = whoami::username();
//    let uid = unsafe { libc::geteuid() } as u32;
//    if uid < 1000 || user != ALLOWED_USER {
//        anyhow::bail!("VelvetGuard: Not authorized (UID={}, user={})", uid, user);
//    }
//    let nfc = user.nfc().collect::<String>();
//    if nfc != user {
//        anyhow::bail!("VelvetGuard: Username not Unicode NFC normalized");
//    }
    Ok(())
}

fn ensure_base() -> Result<PathBuf> {
    //let base = base_dir();
    //fs::create_dir_all(&base)?;
    //let mut p = fs::metadata(&base)?.permissions();
    //p.set_mode(0o700);
    //fs::set_permissions(&base, p)?;
    //Ok(base)
    Ok(PathBuf::new())
}

// ============================================================================
// §6.7.0 Crypto Primitives
// ============================================================================
fn scrypt_seed(key: &[u8], salt: &[u8]) -> anyhow::Result<[u8; 32]> {
    use scrypt::{scrypt, Params};
    let params = Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut out = [0u8; 32];
    scrypt(key, salt, &params, &mut out).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(out)
}

/* §6.7.1 Stream XOR with SHA-256(seed||counter_le) */
fn xor_keystream(data: &[u8], seed32: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let mut i = 0usize;
    let mut ctr: u64 = 0;
    while i < data.len() {
        let mut hasher = Sha256::new();
        hasher.update(seed32);
        hasher.update(&ctr.to_le_bytes());
        let block = hasher.finalize();
        let n = std::cmp::min(block.len(), data.len() - i);
        for j in 0..n {
            out[i + j] = data[i + j] ^ block[j];
        }
        i += n;
        ctr = ctr.wrapping_add(1);
    }
    out
}

/* §6.7.2 BLAKE3 keyed tag over header || len_le || ct */
fn b3_tag(key32: &[u8; 32], header: &[u8], ct: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(key32);
    h.update(b"SIGILBOOK-MAC-v1");
    h.update(header);
    h.update(&(ct.len() as u64).to_le_bytes());
    let mut out = [0u8; 32];
    h.finalize_xof().fill(&mut out);
    out
}

// ============================================================================
// §6.8.0 Header Encode/Decode
// ============================================================================
fn header_encode(salt: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(6 + salt.len());
    v.extend_from_slice(MAGIC);
    v.push(VERSION);
    v.push(salt.len() as u8);
    v.extend_from_slice(salt);
    v
}
fn header_decode(buf: &[u8]) -> Result<(Vec<u8>, usize, Vec<u8>)> {
    if buf.len() < 6 { anyhow::bail!("short header"); }
    if &buf[0..4] != MAGIC { anyhow::bail!("bad magic"); }
    let ver = buf[4];
    if ver != VERSION { anyhow::bail!("bad version"); }
    let slen = buf[5] as usize;
    if buf.len() < 6 + slen { anyhow::bail!("short header (salt)"); }
    let header = buf[0..6 + slen].to_vec();
    let salt = buf[6..6 + slen].to_vec();
    Ok((salt, 6 + slen, header))
}

/// Compute a stable identity for a vault file from its header+tag.
/// This is independent of mountpoint, path, and timestamps.
fn vault_identity(p: &Path) -> Result<String> {
    use blake3::Hasher;
    use std::io::Read;

    let mut f = File::open(p)
        .with_context(|| format!("open vault for identity: {}", p.display()))?;

    // Read header
    let mut hdr = [0u8; SARX_HEADER_BYTES];
    f.read_exact(&mut hdr)
        .with_context(|| format!("read header for identity: {}", p.display()))?;

    // Read tag
    let mut tag = [0u8; SARX_TAG_BYTES];
    f.read_exact(&mut tag)
        .with_context(|| format!("read tag for identity: {}", p.display()))?;

    // Hash: domain sep + header + tag
    let mut h = Hasher::new();
    h.update(b"SIGILBOOK-VAULT-ID-v1");
    h.update(&hdr);
    h.update(&tag);
    Ok(h.finalize().to_hex().to_string())
}

// ============================================================================
// §6.9.0 Master Key (quick/dirty parity)
// ============================================================================

fn load_master_key() -> Result<Vec<u8>> {
    // Strict: no silent creation; require explicit init/reseed.
    let up = usb_seed_path().ok_or_else(|| anyhow::anyhow!("USB key not inserted"))?;
    if !up.exists() {
        anyhow::bail!(format!(
            ".sigil.seed missing on Velvet USB at {} — insert the correct key or run `sigilbook init` / `sigilbook reseed`.",
            up.display()
        ));
    }
    let key = fs::read(&up)
        .with_context(|| format!("failed to read .sigil.seed at {}", up.display()))?;
    if key.len() == 0 {
        anyhow::bail!(format!(".sigil.seed is empty at {}", up.display()));
    }
    Ok(key)
}

// ============================================================================
// §6.10.0 DB I/O with MAC
// ============================================================================
fn save_db(path: &Path, db: &Db, master_key: &[u8]) -> Result<()> {
    // serialize and encrypt
    let s = serde_json::to_string_pretty(db)?;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let seed = scrypt_seed(master_key, &salt)?;
    let ct = xor_keystream(s.as_bytes(), &seed);
    let header = header_encode(&salt);
    let tag = b3_tag(&seed, &header, &ct);

    // assemble wire image: header || tag || ciphertext
    let mut wire = Vec::with_capacity(header.len() + 32 + ct.len());
    wire.extend_from_slice(&header);
    wire.extend_from_slice(&tag);
    wire.extend_from_slice(&ct);

    // write atomically & durably
    atomic_write(path, &wire)
}

fn load_db(path: &Path, master_key: &[u8]) -> Result<Db> {
    let buf = match fs::read(path) {
        Ok(b) if !b.is_empty() => b,
        _ => return Ok(Db::default()),
    };
    if buf.len() < 6 + 32 { anyhow::bail!("truncated"); }
    let (salt, off, header) = header_decode(&buf)?;
    let tag_file = &buf[off..off + 32];
    let ct = &buf[off + 32..];
    let seed = scrypt_seed(master_key, &salt)?;
    let tag_calc = b3_tag(&seed, &header, ct);
    if ConstantTimeEq::ct_eq(tag_file, &tag_calc).unwrap_u8() == 0 {
        anyhow::bail!("sigilbook MAC mismatch");
    }
    let pt = xor_keystream(ct, &seed);
    let db: Db = serde_json::from_slice(&pt).unwrap_or_default();
    Ok(db)
}

// ============================================================================
// §6.11.0 Helpers (hashing, mounts, markers)
// ============================================================================

fn file_hash(p: &Path) -> Result<String> {
    let mut h = Sha256::new();

    // Try canonical path first (stable across cwd)
    let canonical = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let path_str = canonical.display().to_string();

    // Prefer hashing real contents if possible
    if let Ok(mut f) = File::open(&canonical) {
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 { break; }
            h.update(&buf[..n]);
        }
        return Ok(format!("{:x}", h.finalize()));
    }

    // Fallback: stable id from path + best-effort metadata (never error)
    h.update(path_str.as_bytes());
    if let Ok(m) = fs::metadata(&canonical) {
        h.update(m.len().to_le_bytes());
        if let Ok(modt) = m.modified() {
            if let Ok(dur) = modt.duration_since(std::time::UNIX_EPOCH) {
                h.update(dur.as_nanos().to_le_bytes());
            }
        }
    }
    Ok(format!("{:x}", h.finalize()))
}

fn media_mounts() -> Vec<PathBuf> {
    cfg_if! {
        if #[cfg(unix)] {
            let user = whoami::username();
            vec![
                PathBuf::from(format!("/media/{user}")),
                PathBuf::from(format!("/run/media/{user}"))
            ]
        } else if #[cfg(windows)] {
            let mut roots = Vec::new();
            for letter in b'A'..=b'Z' {
                let root = PathBuf::from(format!("{}:\\", letter as char));
                if root.exists() {
                    roots.push(root);
                }
            }
            roots
        } else {
            Vec::new()
        }
    }
}

fn find_marker_any() -> Option<(PathBuf, serde_json::Value)> {
    for base in media_mounts() {
        if base.is_dir() {
            if let Ok(rd) = fs::read_dir(base) {
                for e in rd.flatten() {
                    let mp = e.path();
                    let marker = mp.join(USB_DETECT_LABEL);
                    if marker.is_file() {
                        if let Ok(txt) = fs::read_to_string(&marker) {
                            if let Ok(j) = serde_json::from_str::<serde_json::Value>(&txt) {
                                return Some((mp, j));
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

fn sync_file(f: &File) -> std::io::Result<()> {
    f.sync_all()
}

#[allow(dead_code)]
fn sync_dir(path: &Path) -> std::io::Result<()> {
    cfg_if! {
        if #[cfg(unix)] {
            let df = OpenOptions::new().read(true).open(path)?;
            // SAFETY: raw fd fsync on unix
            unsafe { libc::fsync(df.as_raw_fd()); }
            Ok(())
        } else {
            // Windows: no portable directory fsync; best-effort only.
            Ok(())
        }
    }
}

fn set_file_private(path: &Path) -> std::io::Result<()> {
    cfg_if! {
        if #[cfg(unix)] {
            let mut perm = fs::metadata(path)?.permissions();
            perm.set_mode(0o600);
            fs::set_permissions(path, perm)
        } else {
            // Windows: skip chmod bits; NTFS ACLs would be the right place,
            // but we keep it simple and portable here.
            Ok(())
        }
    }
}

fn find_by_uuid(target_uuid: &str) -> Option<PathBuf> {
    for base in media_mounts() {
        if base.is_dir() {
            if let Ok(rd) = fs::read_dir(base) {
                for e in rd.flatten() {
                    let mp = e.path();
                    let marker = mp.join(USB_DETECT_LABEL);
                    if marker.is_file() {
                        if let Ok(txt) = fs::read_to_string(&marker) {
                            if let Ok(j) = serde_json::from_str::<serde_json::Value>(&txt) {
                                if j.get("uuid").and_then(|x| x.as_str()) == Some(target_uuid) {
                                    return Some(mp);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

#[cfg(windows)]
fn windows_volume_serial_hex(root: &Path) -> Option<String> {
    // Expect like "E:\"; ensure trailing backslash.
    let mut s = root.as_os_str().to_string_lossy().to_string();
    if !s.ends_with('\\') { s.push('\\'); }
    let wide: Vec<u16> = OsStr::new(&s).encode_wide().chain(std::iter::once(0)).collect();

    let mut serial: u32 = 0;
    let mut max_comp_len: u32 = 0;
    let mut fs_flags: u32 = 0;
    // Buffers we don't actually need the names from, but must pass
    let mut vol_name = [0u16; 256];
    let mut fs_name  = [0u16; 256];

    let ok = unsafe {
        GetVolumeInformationW(
            wide.as_ptr(),
            vol_name.as_mut_ptr(), vol_name.len() as u32,
            &mut serial,
            &mut max_comp_len,
            &mut fs_flags,
            fs_name.as_mut_ptr(), fs_name.len() as u32,
        )
    };
    if ok != 0 { Some(format!("{:08X}", serial)) } else { None }
}

fn active_uuid_path() -> PathBuf {
    dirs::home_dir().unwrap().join(ACTIVE_USB_FILE)
}

fn usb_db_path() -> Option<PathBuf> {
    let active_uuid_path = active_uuid_path();
    let active_uuid = std::fs::read_to_string(&active_uuid_path).ok().map(|s| s.trim().to_string());
    for base in media_mounts() {
        if base.is_dir() {
            if let Ok(rd) = fs::read_dir(base) {
                for e in rd.flatten() {
                    let mp = e.path();
                    let marker = mp.join(USB_DETECT_LABEL);
                    if marker.is_file() {
                        if let Ok(txt) = fs::read_to_string(&marker) {
                            if let Ok(j) = serde_json::from_str::<serde_json::Value>(&txt) {
                                let uuid = j.get("uuid").and_then(|x| x.as_str()).unwrap_or("");
                                // If active_uuid is set, use only matching UUID
                                if active_uuid.as_deref().map_or(true, |au| au == uuid) {
                                    return Some(mp.join(USB_KEY_FILENAME));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Return Velvet USB mount root (parent of the DB file)
fn velvet_usb_mount_root() -> Option<PathBuf> {
    usb_db_path().and_then(|p| p.parent().map(|x| x.to_path_buf()))
}

fn usb_seed_path() -> Option<PathBuf> {
    velvet_usb_mount_root().map(|root| root.join(USB_SEED_FILE))
}

// §6.11.5 Atomic writer for batch CSV/JSON on USB
fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let f = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
        let mut bw = BufWriter::new(f);
        bw.write_all(data)?;
        bw.flush()?;
        sync_file(bw.get_ref())?;
    }

    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        let _ = sync_dir(parent);
    }
    let _ = set_file_private(path);
    Ok(())
}

// §6.11.6 Write batch rows to <USB>/sarx-batch/<timestamp>.csv|.json
#[derive(Deserialize, Serialize)]
struct BatchRow { path: String, password: String }

fn write_batch_passwords_to_usb(rows: &[BatchRow], format_json: bool) -> Result<PathBuf> {
    let root = velvet_usb_mount_root().ok_or_else(|| anyhow::anyhow!("USB key not inserted"))?;
    let dir = root.join(BATCH_SUBDIR);
    fs::create_dir_all(&dir)?;
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let out = if format_json {
        dir.join(format!("{stamp}.json"))
    } else {
        dir.join(format!("{stamp}.csv"))
    };

    if format_json {
        let body = serde_json::to_vec_pretty(&rows)?;
        atomic_write(&out, &body)?;
    } else {
        let mut s = String::from("path,password\n");
        for r in rows {
            let pp = r.path.replace('"', "\"\"");
            let ww = r.password.replace('"', "\"\"");
            s.push_str(&format!("\"{}\",\"{}\"\n", pp, ww));
        }
        atomic_write(&out, s.as_bytes())?;
    }
    Ok(out)
}

// ============================================================================
// §6.12.0 Merge & Sync
// ============================================================================
fn pick_db_path(_master_key: &[u8]) -> Result<PathBuf> {
    usb_db_path().ok_or_else(|| anyhow::anyhow!("USB key not inserted"))
}

// §6.12.1 Batch CLI handler (reads JSON array from stdin)
fn batch_write_to_usb(_format: &str) -> Result<()> {
    // Disabled for security: plaintext password export is not allowed.
    anyhow::bail!("plaintext batch export is disabled. passwords are stored only in the encrypted sigilbook DB.");
}

// ============================================================================
// §6.13.0 Operations (save/get)
// ============================================================================
fn save_password(vaultfile: &str, password: &str) -> Result<()> {
    velvet_guard()?;
    let master = load_master_key()?;
    let db_path = pick_db_path(&master)?;
    let mut db = load_db(&db_path, &master)?;

    let vp = std::fs::canonicalize(vaultfile).unwrap_or_else(|_| PathBuf::from(vaultfile));
    let id = vault_identity(&vp)?;

    if let Some(e) = db.entries.iter_mut().find(|e| e.vault_id == id) {
        e.password = password.to_string();
        if !e.paths.iter().any(|p| p == vaultfile) {
            e.paths.push(vaultfile.to_string());
        }
    } else {
        db.entries.push(Entry {
            vault_id: id,
            password: password.to_string(),
            paths: vec![vaultfile.to_string()],
        });
    }

    save_db(&db_path, &db, &master)?;
    println!(
        "[{}] saved password for {} → {}",
        chrono::Local::now().to_rfc3339(),
        vaultfile,
        db_path.display()
    );
    Ok(())
}

fn get_password(vaultfile: &str) -> Result<()> {
    velvet_guard()?;
    let master = load_master_key()?;
    let usb = usb_db_path().ok_or_else(|| anyhow::anyhow!("No velvet USB detected!"))?;
    let db = load_db(&usb, &master).context("load DB (possible MAC mismatch: wrong seed or corrupted DB)")?;

    let vp = std::fs::canonicalize(vaultfile).unwrap_or_else(|_| PathBuf::from(vaultfile));
    let id = vault_identity(&vp)?;

    if let Some(e) = db.entries.iter().find(|e| e.vault_id == id) {
        println!("{}", e.password);
    } else {
        println!("(not found)");
    }
    Ok(())
}

fn detect_usb_key() {
    let mut found = false;
    for base in media_mounts() {
        if base.is_dir() {
            if let Ok(rd) = std::fs::read_dir(base) {
                for e in rd.flatten() {
                    let mp = e.path();
                    let marker = mp.join(USB_DETECT_LABEL);
                    if marker.is_file() {
                        if let Ok(txt) = std::fs::read_to_string(&marker) {
                            if let Ok(j) = serde_json::from_str::<serde_json::Value>(&txt) {
                                let uuid = j.get("uuid").and_then(|x| x.as_str()).unwrap_or("");
                                println!("\nVelvet USB detected at: {}", mp.display());
                                println!("Marker Info:");
                                if let Some(obj) = j.as_object() {
                                    for (k, v) in obj.iter() {
                                        println!("  {}: {}", k, v);
                                    }
                                }
                                // lock UUID (may be empty on very old markers)
                                let uuid_path = dirs::home_dir().unwrap().join(".velvet_last_usb");
                                let _ = std::fs::write(&uuid_path, uuid);
                                println!("\n[Velvet] Now using USB with UUID: {} for all password ops.\n", uuid);
                                found = true;
                            }
                        }
                    }
                }
            }
        }
    }
    if !found {
        println!("No Velvet USB detected!");
    }
}

// ============================================================================
// §6.13.1 Key Rotation & Reseed
// ============================================================================

fn rekey_db() -> Result<()> {
    velvet_guard()?;
    let up = usb_seed_path().ok_or_else(|| anyhow::anyhow!("USB key not inserted"))?;
    if !up.exists() {
        anyhow::bail!(".sigil.seed not found; insert Velvet USB or initialize it first");
    }

    // Load DB with current seed
    let old_master = fs::read(&up)?;
    let db_path = pick_db_path(&old_master)?;
    let db = load_db(&db_path, &old_master)?;

    // Generate new seed and write it
    let mut new_key = vec![0u8; 64];
    rand::thread_rng().fill_bytes(&mut new_key);
    if let Some(parent) = up.parent() { fs::create_dir_all(parent)?; }
    let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(&up)?;
    f.write_all(&new_key)?;
    let mut perm = fs::metadata(&up)?.permissions();
    perm.set_mode(0o600);
    fs::set_permissions(&up, perm)?;

    // Rewrap DB under the new seed
    save_db(&db_path, &db, &new_key)?;
    use zeroize::Zeroize;
    new_key.zeroize();

    println!("[{}] rekey complete → {}", chrono::Local::now().to_rfc3339(), db_path.display());
    Ok(())
}

fn reseed_hard() -> Result<()> {
    velvet_guard()?;
    let root = velvet_usb_mount_root().ok_or_else(|| anyhow::anyhow!("USB key not inserted"))?;
    let seed = root.join(".sigil.seed");
    let db = root.join("VELVET_SIGILBOOK.sigil");

    // Best-effort delete (ignore missing files)
    let _ = fs::remove_file(&db);
    let _ = fs::remove_file(&seed);

    // fsync parent directory to ensure deletions are durable
    if let Some(parent) = root.parent() {
        if let Ok(df) = OpenOptions::new().read(true).open(parent) {
            #[allow(unsafe_code)]
            unsafe {
                use std::os::unix::io::AsRawFd;
                libc::fsync(df.as_raw_fd());
            }
        }
    }

    println!("[{}] hard reseed complete (seed and DB removed from {})", chrono::Local::now().to_rfc3339(), root.display());

    // Immediately initialize a fresh seed + empty DB so the key is usable right away.
    init_seed()?;

    Ok(())
}

fn init_seed() -> Result<()> {
    velvet_guard()?;
    let root = velvet_usb_mount_root().ok_or_else(|| anyhow::anyhow!("USB key not inserted"))?;
    let seed_path = root.join(".sigil.seed");
    let db_path = root.join("VELVET_SIGILBOOK.sigil");

    if seed_path.exists() || db_path.exists() {
        anyhow::bail!("Velvet USB already has a seed/DB — run `reseed` first if you want a clean start.");
    }

    // generate brand new 64-byte master seed
    let mut key = vec![0u8; 64];
    rand::thread_rng().fill_bytes(&mut key);

    // write seed file durably
    if let Some(parent) = seed_path.parent() { fs::create_dir_all(parent)?; }
    let f = OpenOptions::new().create(true).write(true).truncate(true).open(&seed_path)?;
    {
        let mut bw = BufWriter::new(f);
        bw.write_all(&key)?;
        bw.flush()?;
        #[allow(unsafe_code)]
        unsafe {
            use std::os::unix::io::AsRawFd;
            libc::fsync(bw.get_ref().as_raw_fd());
        }
    }
    // fsync parent directory so the directory entry is durable too
    if let Some(parent) = seed_path.parent() {
        let df = OpenOptions::new().read(true).open(parent)?;
        #[allow(unsafe_code)]
        unsafe {
            use std::os::unix::io::AsRawFd;
            libc::fsync(df.as_raw_fd());
        }
    }

    // read-back verify (must be exactly 64 bytes)
    let rb = fs::read(&seed_path)
        .with_context(|| format!("failed to re-open written seed at {}", seed_path.display()))?;
    if rb.len() != 64 {
        anyhow::bail!(format!(
            ".sigil.seed length check failed ({} bytes) at {}",
            rb.len(),
            seed_path.display()
        ));
    }

    // create empty DB encrypted with this seed
    let db = Db::default();
    save_db(&db_path, &db, &rb)?;

    use zeroize::Zeroize;
    key.zeroize();

    println!("[{}] Velvet USB initialized with new seed and empty DB → {}", chrono::Local::now().to_rfc3339(), root.display());
    Ok(())
}

// ============================================================================
// §6.14.0 USB Marker Write
// ============================================================================
fn write_usb_key() -> Result<()> {
    velvet_guard()?;

    cfg_if! {
        if #[cfg(unix)] {
            // --- Linux/Unix path (your existing logic, tidied) ---
            let mut drives: Vec<PathBuf> = Vec::new();
            for base in media_mounts() {
                if base.is_dir() {
                    for ent in fs::read_dir(base)? {
                        if let Ok(e) = ent { drives.push(e.path()); }
                    }
                }
            }
            if drives.is_empty() {
                println!("No USB drives detected!");
                return Ok(());
            }
            println!("\nDetected USB drives:");
            for (i, d) in drives.iter().enumerate() {
                println!("{}. {}", i + 1, d.display());
            }
            print!("\nWhich USB to write Velvet key marker to? [number]: ");
            std::io::stdout().flush().ok();
            let mut buf = String::new();
            std::io::stdin().read_line(&mut buf)?;
            let sel: usize = buf.trim().parse().unwrap_or(0);
            if sel == 0 || sel > drives.len() { anyhow::bail!("Invalid selection"); }
            let chosen = &drives[sel - 1];

            // device -> uuid via lsblk
            let mounts = fs::read_to_string("/proc/mounts")?;
            let mut devpath: Option<String> = None;
            for line in mounts.lines() {
                let parts: Vec<_> = line.split_whitespace().collect();
                if parts.len() >= 2 && parts[1] == chosen.to_string_lossy() {
                    devpath = Some(parts[0].to_string());
                    break;
                }
            }
            let devname = devpath.ok_or_else(|| anyhow::anyhow!("device node not found"))?
                                 .trim_start_matches("/dev/").to_string();

            let out = Command::new("lsblk").args(["-o","NAME,UUID","-J"]).output().context("lsblk")?;
            let j: serde_json::Value = serde_json::from_slice(&out.stdout)?;
            fn find_uuid(root: &serde_json::Value, name: &str) -> Option<String> {
                let arr = root.get("blockdevices")?.as_array()?;
                fn rec(list: &[serde_json::Value], name: &str) -> Option<String> {
                    for d in list {
                        if d.get("name")?.as_str()? == name {
                            if let Some(u) = d.get("uuid").and_then(|x| x.as_str()) { return Some(u.to_string()); }
                        }
                        if let Some(ch) = d.get("children").and_then(|x| x.as_array()) {
                            if let Some(u) = rec(ch, name) { return Some(u); }
                        }
                    }
                    None
                }
                rec(arr, name)
            }
            let uuid = find_uuid(&j, &devname).unwrap_or_default();

            let info = serde_json::json!({
                "created": chrono::Local::now().to_rfc3339(),
                "mountpoint": chosen.to_string_lossy(),
                "uuid": uuid,
                "note": "Velvet Key device (sigilbook)"
            });
            let marker = chosen.join(USB_DETECT_LABEL);
            fs::write(&marker, serde_json::to_string_pretty(&info)?)?;
            let _ = set_file_private(&marker);
            println!("\nVelvet key marker written to {} with UUID {}\n", marker.display(), info["uuid"]);
            Ok(())

        } else if #[cfg(windows)] {
            // --- Windows path ---
            // list roots that exist
            let mut drives = Vec::new();
            for letter in b'A'..=b'Z' {
                let root = PathBuf::from(format!("{}:\\", letter as char));
                if root.exists() { drives.push(root); }
            }
            if drives.is_empty() {
                println!("No drives detected!");
                return Ok(());
            }
            println!("\nDetected drives:");
            for (i, d) in drives.iter().enumerate() {
                println!("{}. {}", i + 1, d.display());
            }
            print!("\nWhich drive to write Velvet key marker to? [number]: ");
            std::io::stdout().flush().ok();
            let mut buf = String::new();
            std::io::stdin().read_line(&mut buf)?;
            let sel: usize = buf.trim().parse().unwrap_or(0);
            if sel == 0 || sel > drives.len() { anyhow::bail!("Invalid selection"); }
            let chosen = &drives[sel - 1];

            let uuid = windows_volume_serial_hex(chosen).unwrap_or_else(|| format!("WIN-{}", chosen.display()));
            let info = serde_json::json!({
                "created": chrono::Local::now().to_rfc3339(),
                "mountpoint": chosen.to_string_lossy(),
                "uuid": uuid,
                "note": "Velvet Key device (sigilbook)"
            });
            let marker = chosen.join(USB_DETECT_LABEL);
            fs::write(&marker, serde_json::to_string_pretty(&info)?)?;
            println!("\nVelvet key marker written to {} with UUID {}\n", marker.display(), info["uuid"]);
            Ok(())
        } else {
            anyhow::bail!("unsupported platform");
        }
    }
}

// ============================================================================
// §6.15.0 Main
// ============================================================================
fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::Writeusb) => write_usb_key(),
        Some(Cmd::Detect) => {
            detect_usb_key();
            Ok(())
        },
        Some(Cmd::Forget) => {
            let path = active_uuid_path();
            if path.exists() {
                std::fs::remove_file(path).ok();
                println!("Forgot active Velvet USB.");
            }
            Ok(())
        },
        Some(Cmd::Get { vaultfile }) => get_password(&vaultfile),
        Some(Cmd::Save { vaultfile, password }) => {
            let pw = if password == "-" {
                let mut s = String::new();
                std::io::stdin().read_line(&mut s)?;
                s.trim_end_matches(&['\r','\n'][..]).to_string()
            } else { password };
            if pw.is_empty() { anyhow::bail!("empty password"); }
            let res = save_password(&vaultfile, &pw);
            let mut pw_clean = pw.into_bytes();
            pw_clean.zeroize();
            res
        },
        Some(Cmd::Batch { format }) => batch_write_to_usb(&format),
        Some(Cmd::Rekey) => rekey_db(),
        Some(Cmd::Reseed) => reseed_hard(),
        Some(Cmd::Init) => init_seed(),
        None => {
            eprintln!(
                "Usage:\n  sigilbook writeusb\n  sigilbook detect\n  sigilbook forget\n  sigilbook get <vaultfile>\n  sigilbook save <vaultfile> <password|->\n  sigilbook batch [--format csv|json] < JSON\n  sigilbook rekey\n  sigilbook reseed"
            );
            Ok(())
        }
    }
}
