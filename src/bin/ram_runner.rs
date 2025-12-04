// src/bin/ram_runner.rs
// Velvet RAM Runner — loads .vault files from a "preload USB" into /dev/shm,
// using Sigilbook (separate USB) for passwords. Enforces strict isolation:
// if any Sigilbook artifact is found on the preload USB, abort.
//
// Linux-only target assumed. No secrets written to disk. No PAM.
// Decrypts in-process via SARX library; never calls sarx_decrypt.
//
// Build: part of the existing Cargo workspace alongside sarx & sigilbook.
//
// Behavior summary:
// - Scan /media/$USER and /run/media/$USER for mounts that contain "velvet_preload/"
// - For each such mount (a "preload USB"):
//     * Abort if forbidden Sigilbook artifacts exist on that same USB
//     * Recursively find *.vault inside velvet_preload/
//     * For each vault, fetch password via "sigilbook get <vault_path>"
//         - If not found, skip
//         - If found, decrypt to /dev/shm/velvet_preload/<mount_name>/<relative_path-without-.vault>
// - Poll every 2s; when a preload USB goes away, wipe its RAM subtree.

use anyhow::{Context, Result};
use std::{
    collections::{HashMap, HashSet},
    env,
    ffi::OsStr,
    fs,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

use zeroize::Zeroize;

use sarx::headers::{SARX_HEADER_BYTES, SARX_TAG_BYTES, VaultHeader};
use sarx::sarx::{generate_config_with_timestamp, generate_stream};
use subtle::ConstantTimeEq;

// --------- Config knobs (safe defaults) ---------

const POLL_SECS: u64 = 2;
const PRELOAD_DIRNAME: &str = "velvet_preload"; // Can rename to "sarx_preload" later if you wish
const RAM_ROOT: &str = "/dev/shm/ram_runner";

// Forbid running if *any* of these names (case-insensitive) appear on the preload USB (root OR inside preload dir)
const FORBIDDEN_NAMES: &[&str] = &[
    "sigilbook",
    "sigilbook-rust",
    "sigilbook.exe",
    ".sigil.seed",
    "velvet_sigilbook.sigil",
    "sigilbook-rust.sigil",
    "velvetkey.info",
];

// Skip non-vault files for maximum safety.
// If you want to copy non-vaults into RAM too, set to true.
const COPY_NON_VAULTS_TO_RAM: bool = false;

// RAM file/dir permissions (best-effort on Unix)
#[cfg(unix)]
fn set_private_perms(path: &Path, is_dir: bool) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mut perm = meta.permissions();
        perm.set_mode(if is_dir { 0o700 } else { 0o600 });
        let _ = fs::set_permissions(path, perm);
    }
}
#[cfg(not(unix))]
fn set_private_perms(_path: &Path, _is_dir: bool) {}

// --------- Mount helpers ---------

fn all_mount_roots() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/media/"),
        PathBuf::from("/run/media/"),
    ]
}

fn find_preload_mounts() -> Vec<(PathBuf, PathBuf)> {
    let mut out = Vec::new();

    for base in all_mount_roots() {
        if !base.is_dir() { continue; }

        // Level 1: entries directly under /media or /run/media
        if let Ok(l1) = fs::read_dir(&base) {
            for e1 in l1.flatten() {
                let p1 = e1.path();
                if !p1.is_dir() { continue; }

                // Case A: some distros mount straight under /media/<label>
                let p1_preload = p1.join(PRELOAD_DIRNAME);
                if p1_preload.is_dir() {
                    out.push((p1.clone(), p1_preload));
                }

                // Level 2: common case /media/<user>/<label>
                if let Ok(l2) = fs::read_dir(&p1) {
                    for e2 in l2.flatten() {
                        let p2 = e2.path();
                        if !p2.is_dir() { continue; }
                        let p2_preload = p2.join(PRELOAD_DIRNAME);
                        if p2_preload.is_dir() {
                            out.push((p2.clone(), p2_preload));
                        }
                    }
                }
            }
        }
    }

    out
}

fn lc_name(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(OsStr::to_str)
        .map(|s| s.to_ascii_lowercase())
}

fn contains_forbidden_artifacts(mount_root: &Path, preload_dir: &Path) -> bool {
    // Check top-level of mount + top-level of preload_dir
    let mut check_dir = |dir: &Path| -> bool {
        if let Ok(rd) = fs::read_dir(dir) {
            for e in rd.flatten() {
                if let Some(name) = lc_name(&e.path()) {
                    if FORBIDDEN_NAMES.iter().any(|f| name.starts_with(&f.to_ascii_lowercase())) {
                        return true;
                    }
                }
            }
        }
        false
    };
    check_dir(mount_root) || check_dir(preload_dir)
}

fn mount_token(mount_root: &Path) -> String {
    // A stable-ish token for the mount (used under /dev/shm). Use last path component.
    mount_root
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("mount")
        .to_string()
}

// --------- Recursive listing ---------

fn gather_vaults(root: &Path) -> Vec<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    let mut out = Vec::new();
    while let Some(dir) = stack.pop() {
        if let Ok(rd) = fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p
                    .extension()
                    .and_then(|x| x.to_str())
                    .map(|s| s.eq_ignore_ascii_case("vault"))
                    .unwrap_or(false)
                {
                    out.push(p);
                } else if COPY_NON_VAULTS_TO_RAM {
                    // (handled later)
                    out.push(p);
                }
            }
        }
    }
    out
}

// --------- Sigilbook integration ---------

fn sibling_dir() -> PathBuf {
    let exe = env::current_exe().ok();
    exe.and_then(|p| p.parent().map(|q| q.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn sibling_path(bin: &str) -> PathBuf {
    let mut p = sibling_dir();
    #[cfg(windows)]
    {
        p.push(format!("{bin}.exe"));
    }
    #[cfg(not(windows))]
    {
        p.push(bin);
    }
    p
}

fn sigilbook_path() -> PathBuf {
    sibling_path("sigilbook")
}

fn sigilbook_get_password(vault_path: &Path) -> Result<Option<Vec<u8>>> {
    // Calls: sigilbook get <vaultfile>
    // On success: stdout = password\n
    // If not found: prints "(not found)"
    let out = Command::new(sigilbook_path())
        .arg("get")
        .arg(vault_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| "launch sigilbook get")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("sigilbook get failed: {}", stderr.trim());
    }
    let mut pw = out.stdout;
    // Trim trailing \r?\n
    while let Some(b) = pw.last() {
        if *b == b'\n' || *b == b'\r' {
            pw.pop();
        } else {
            break;
        }
    }
    // "(not found)" sentinel
    if pw.eq(b"(not found)") || pw.is_empty() {
        Ok(None)
    } else {
        Ok(Some(pw))
    }
}

// --------- SARX decryption in-process (to RAM) ---------

fn decrypt_vault_to_ram(
    vault_path: &Path,
    password_utf8: &str,
    dest_dir: &Path,
) -> Result<PathBuf> {
    // Open source vault & read header/tag
    let mut fin = File::open(vault_path)
        .with_context(|| format!("open {}", vault_path.display()))?;

    // Header
    let mut hdr = [0u8; SARX_HEADER_BYTES];
    fin.read_exact(&mut hdr).context("read header")?;
    let (header, header_raw) =
        VaultHeader::decode_with_raw(&hdr).context("decode header")?;

    // Tag
    let mut tag_file = [0u8; SARX_TAG_BYTES];
    fin.read_exact(&mut tag_file).context("read tag")?;

    // Size & extent
    let meta = fin.metadata()?;
    let total_len = meta.len();
    if total_len < (SARX_HEADER_BYTES + SARX_TAG_BYTES) as u64 {
        anyhow::bail!("invalid vault (too small)");
    }
    let clen = (total_len as usize) - (SARX_HEADER_BYTES + SARX_TAG_BYTES);
    let ct_start = (SARX_HEADER_BYTES + SARX_TAG_BYTES) as u64;

    // Derive k_stream/k_mac with Argon2id using header params
    if header.kdf_id != 2 {
        anyhow::bail!("unsupported kdf_id (expected Argon2id v1.3)");
    }
    if !(1..=10).contains(&header.t_cost) {
        anyhow::bail!("t_cost out of range");
    }
    if !(10..=24).contains(&header.m_cost) {
        anyhow::bail!("m_cost out of range");
    }
    if !(1..=4).contains(&header.lanes) {
        anyhow::bail!("lanes out of range");
    }

    let pass_bytes = password_utf8.as_bytes().len();
    let k_stream_len = ((pass_bytes + 31) & !31).max(32);
    let okm_len = k_stream_len + 32;
    let mut okm = vec![0u8; okm_len];
    {
        use argon2::{Algorithm, Argon2, Params, Version};
        let mem_kib: u32 = 1u32 << header.m_cost;
        let params =
            Params::new(mem_kib, header.t_cost.into(), header.lanes.into(), Some(okm_len))
                .expect("argon2 params");
        let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        a2.hash_password_into(password_utf8.as_bytes(), &header.salt32, &mut okm)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    }
    let (k_stream, k_mac) = okm.split_at(k_stream_len);
    let mut k_mac32 = [0u8; 32];
    k_mac32.copy_from_slice(&k_mac[..32]);

    // Verify MAC over domain || header_raw || len_le || ciphertext
    let mut mac = blake3::Hasher::new_keyed(&k_mac32);
    mac.update(b"SARX2DU-MAC-v1");
    mac.update(&header_raw);
    mac.update(&(clen as u64).to_le_bytes());

    fin.seek(SeekFrom::Start(ct_start))?;
    let mut buf = vec![0u8; 16 * 1024 * 1024];
    let mut left = clen;
    while left > 0 {
        let n = left.min(buf.len());
        fin.read_exact(&mut buf[..n])?;
        mac.update(&buf[..n]);
        left -= n;
    }
    let mut tag_calc = [0u8; 32];
    mac.finalize_xof().fill(&mut tag_calc);

    if ConstantTimeEq::ct_eq(&tag_calc[..], &tag_file[..]).unwrap_u8() == 0 {
        okm.zeroize();
        anyhow::bail!("MAC mismatch (wrong password or corrupted file)");
    }

    // Build SARX config + postmix and stream-decrypt into /dev/shm
    fin.seek(SeekFrom::Start(ct_start))?;

    let cfg =
        generate_config_with_timestamp(password_utf8, None, 0, header.timestamp_ns)?;
    let mut postmix = Vec::with_capacity(16 + k_stream_len + 12 + 8);
    postmix.extend_from_slice(b"SARX2DU-POST\0\0\0\0");
    postmix.extend_from_slice(k_stream);
    postmix.extend_from_slice(&header.nonce12);
    postmix.extend_from_slice(&header.timestamp_ns.to_be_bytes());

    // Derive relative path under preload dir, then map to RAM dest, stripping ".vault"
    // We expect caller to supply dest_dir that corresponds to RAM mount of a specific preload root,
    // and vault_path is *inside* that preload root (validated upstream).
    let out_rel = strip_vault_suffix(
        vault_path.file_name().and_then(|n| n.to_str()).unwrap_or("output"),
    );
    fs::create_dir_all(dest_dir).with_context(|| dest_dir.display().to_string())?;
    set_private_perms(dest_dir, true);

    let out_path = dest_dir.join(out_rel);
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
        set_private_perms(parent, true);
    }
    let mut fout =
        File::create(&out_path).with_context(|| format!("create {}", out_path.display()))?;
    set_private_perms(&out_path, false);

    let mut ct = vec![0u8; 16 * 1024 * 1024];
    let mut pt = vec![0u8; 16 * 1024 * 1024];
    let mut abs_off: u64 = 0;
    let mut remain = clen;

    while remain > 0 {
        let n = remain.min(ct.len());
        fin.read_exact(&mut ct[..n])?;

        // Generate keystream for this slice and XOR
        pt[..n].fill(0);
        generate_stream(&cfg, Some(&postmix), abs_off, n, &mut pt[..n])?;
        for i in 0..n {
            pt[i] ^= ct[i];
        }
        fout.write_all(&pt[..n])?;
        abs_off += n as u64;
        remain -= n;
    }

    fout.flush()?;
    let _ = fout.sync_all();

    // hygiene
    okm.zeroize();
    pt.zeroize();
    ct.zeroize();
    postmix.zeroize();

    Ok(out_path)
}

fn strip_vault_suffix(name: &str) -> String {
    name.strip_suffix(".vault")
        .unwrap_or(name)
        .to_string()
}

// --------- RAM subtree helpers ---------

fn ram_mount_root_for(mount_root: &Path) -> PathBuf {
    let token = mount_token(mount_root);
    Path::new(RAM_ROOT).join(token)
}

fn preload_relative_path(preload_root: &Path, file: &Path) -> PathBuf {
    file.strip_prefix(preload_root).unwrap_or(file).to_path_buf()
}

fn ram_dest_for_file(mount_root: &Path, preload_root: &Path, file: &Path) -> PathBuf {
    let rel = preload_relative_path(preload_root, file);
    let rel_out = PathBuf::from(strip_vault_suffix(
        rel.file_name().and_then(|n| n.to_str()).unwrap_or("output"),
    ));
    ram_mount_root_for(mount_root).join(rel.parent().unwrap_or(Path::new(""))).join(rel_out)
}

fn wipe_ram_for_mount(mount_root: &Path) {
    let ram_root = ram_mount_root_for(mount_root);
    if ram_root.exists() {
        let _ = fs::remove_dir_all(&ram_root);
    }
}

fn picker_mode() -> Result<()> {
    use anyhow::bail;
    use std::io::Write;

    // Base folder to browse: /dev/shm/ram_runner/Programs-Science
    let base = Path::new(RAM_ROOT);
    if !base.is_dir() {
        bail!("No decrypted programs at {}", base.display());
    }

    // 1) list subfolders (BSD, Curiosities, ERT, …)
    let mut folders = fs::read_dir(&base)
        .with_context(|| format!("open {}", base.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.path())
        .collect::<Vec<_>>();
    folders.sort();

    if folders.is_empty() {
        bail!("No subfolders in {}", base.display());
    }

    println!("Subfolders in {}:", base.display());
    for (i, p) in folders.iter().enumerate() {
        println!("  {}. {}", i + 1, p.file_name().and_then(|s| s.to_str()).unwrap_or("?"));
    }
    print!("Choose subfolder [1-{}]: ", folders.len());
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let idx = input.trim().parse::<usize>().unwrap_or(0);
    if idx == 0 || idx > folders.len() {
        bail!("Invalid choice");
    }
    let chosen = &folders[idx - 1];

    // 2) list .py programs in chosen folder
    let mut programs = fs::read_dir(chosen)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().map(|x| x == "py").unwrap_or(false))
        .collect::<Vec<_>>();
    programs.sort();

    if programs.is_empty() {
        bail!("No .py programs in {}", chosen.display());
    }

    println!("\nPrograms in {}:", chosen.display());
    for (i, p) in programs.iter().enumerate() {
        println!("  {}. {}", i + 1, p.file_name().and_then(|s| s.to_str()).unwrap_or("?"));
    }
    print!("Choose program [1-{}]: ", programs.len());
    std::io::stdout().flush().ok();
    input.clear();
    std::io::stdin().read_line(&mut input)?;
    let pidx = input.trim().parse::<usize>().unwrap_or(0);
    if pidx == 0 || pidx > programs.len() {
        bail!("Invalid choice");
    }
    let prog = &programs[pidx - 1];

    println!("\nRunning: {}\n====================================", prog.display());
    let status = Command::new("python3")
        .arg(prog)
        .status()
        .with_context(|| format!("launch python3 {:?}", prog))?;

    if !status.success() {
        bail!("program exited with {}", status);
    }
    Ok(())
}

// --------- Main loop ---------

fn main() -> Result<()> {
    // optional interactive picker: `ram_runner picker`
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("picker") {
        return picker_mode();
    }

    eprintln!("RAM Runner started — strict USB isolation, RAM-only decrypt.");

    // warm RAM root
    fs::create_dir_all(RAM_ROOT)?;
    set_private_perms(Path::new(RAM_ROOT), true);

    // Track active preload mounts so we can wipe their RAM subtree when removed
    let mut active_mounts: HashSet<PathBuf> = HashSet::new();

    loop {
        let mounts = find_preload_mounts();
        eprintln!("Polling for ALL mount roots...");
        for base in all_mount_roots() {
            eprintln!("Checking base mount root: {}", base.display());
            if !base.is_dir() {
                eprintln!("  Not a directory: {}", base.display());
                continue;
            }
            if let Ok(rd) = std::fs::read_dir(&base) {
                for e in rd.flatten() {
                    let mp = e.path();
                    eprintln!("  Found subdir: {}", mp.display());
                    if !mp.is_dir() {
                        eprintln!("    Not a dir: {}", mp.display());
                        continue;
                    }
                    let preload = mp.join(PRELOAD_DIRNAME);
                    if preload.is_dir() {
                        eprintln!("    Found preload dir: {}", preload.display());
                    }
                }
            }
        }
        let mounts = find_preload_mounts();
        eprintln!("Final mounts from find_preload_mounts(): {:?}", mounts);
        let current_set: HashSet<PathBuf> = mounts.iter().map(|(m, _)| m.clone()).collect();

        // Wipe RAM for any mounts that disappeared
        for gone in active_mounts.difference(&current_set) {
            eprintln!(
                "Preload USB removed: {} — wiping its RAM subtree.",
                gone.display()
            );
            wipe_ram_for_mount(gone);
        }
        active_mounts = current_set.clone();

        // Process each preload mount
        for (mount_root, preload_root) in mounts {
            // Isolation barrier
            if contains_forbidden_artifacts(&mount_root, &preload_root) {
                eprintln!(
                    "REFUSING: Sigilbook artifacts present on preload USB at {}. Isolation violated.",
                    mount_root.display()
                );
                continue;
            }

            // RAM subtree for this mount
            let ram_root = ram_mount_root_for(&mount_root);
            fs::create_dir_all(&ram_root)?;
            set_private_perms(&ram_root, true);

            // Gather files
            let files = gather_vaults(&preload_root);

            for path in files {
                // Skip non-vault files unless COPY_NON_VAULTS_TO_RAM is true
                let is_vault = path
                    .extension()
                    .and_then(|x| x.to_str())
                    .map(|s| s.eq_ignore_ascii_case("vault"))
                    .unwrap_or(false);
                if !is_vault {
                    if COPY_NON_VAULTS_TO_RAM {
                        let rel = preload_relative_path(&preload_root, &path);
                        let dest = ram_root.join(rel);
                        if let Some(parent) = dest.parent() {
                            fs::create_dir_all(parent).ok();
                            set_private_perms(parent, true);
                        }
                        if let Err(e) = fs::copy(&path, &dest) {
                            eprintln!(
                                "Copy(non-vault) failed {} → {}: {}",
                                path.display(),
                                dest.display(),
                                e
                            );
                        } else {
                            set_private_perms(&dest, false);
                        }
                    }
                    continue;
                }

                // Already present in RAM with same length? (quick skip)
                let dest_path = ram_dest_for_file(&mount_root, &preload_root, &path);
                if let (Ok(src_meta), Ok(dst_meta)) = (fs::metadata(&path), fs::metadata(&dest_path))
                {
                    // ciphertext length == plaintext length; safe to compare sizes
                    let src_len = src_meta.len();
                    let dst_len = dst_meta.len();
                    if dst_len == src_len {
                        continue; // looks already decrypted
                    }
                }

                // Ask Sigilbook for password
                match sigilbook_get_password(&path) {
                    Ok(Some(pw_bytes)) => {
                        // Interpret as UTF-8 (Sigilbook stored UTF-8)
                        let pw_str = match std::str::from_utf8(&pw_bytes) {
                            Ok(s) => s,
                            Err(_) => {
                                eprintln!(
                                    "Password from Sigilbook is not valid UTF-8 for {}",
                                    path.display()
                                );
                                continue;
                            }
                        };

                        // Decrypt into RAM
                        let out_dir = dest_path
                            .parent()
                            .map(|p| p.to_path_buf())
                            .unwrap_or_else(|| ram_root.clone());
                        if let Err(e) = decrypt_vault_to_ram(&path, pw_str, &out_dir) {
                            eprintln!(
                                "Decrypt failed for {}: {}",
                                path.display(),
                                e
                            );
                        }

                        // hygiene
                        // Zeroize the captured password buffer
                        let mut pw_clean = pw_bytes;
                        pw_clean.zeroize();
                        // pw_str is a &str view into that buffer; already handled.
                    }
                    Ok(None) => {
                        eprintln!(
                            "(skip) No password in Sigilbook for {}",
                            path.display()
                        );
                    }
                    Err(e) => {
                        eprintln!("Sigilbook error for {}: {}", path.display(), e);
                        // If the USB with Sigilbook is missing, there's no point proceeding for this loop.
                        // We'll retry next poll tick.
                        break;
                    }
                }
            }
        }

        thread::sleep(Duration::from_secs(POLL_SECS));
    }
}
