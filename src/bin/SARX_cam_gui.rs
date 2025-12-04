// src/bin/sarx_cam_gui.rs
// SARX SecureCam GUI — multi-cam + mic combos with muxed A/V .vaults
// Build: cargo run --release --bin sarx_cam_gui
// Platform: Linux (v4l2 + CPAL). Requires ffplay in PATH for viewing.

#![cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]

// --- Platform & Standard ---
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write, Seek, SeekFrom, BufWriter},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// --- Universal ---
use anyhow::{Context, Result};
use crossbeam_channel as xchan;
use eframe::egui::{self, ColorImage, TextureHandle, Vec2};
use image::ImageDecoder;
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use sarx::headers::VaultHeader;
use sarx::sarx::{generate_config_with_timestamp, generate_stream, SARXConfig};
use cfg_if::cfg_if;

// --- cpal (audio, always needed) ---
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{SampleFormat, StreamConfig};

// --- v4l2 (Linux only) ---
#[cfg(unix)]
use v4l::buffer::Type as V4lBufType;
#[cfg(unix)]
use v4l::io::mmap::Stream as V4lMmapStream;
#[cfg(unix)]
use v4l::io::traits::CaptureStream;
#[cfg(unix)]
use v4l::video::Capture;
#[cfg(unix)]
use v4l::Device;

// --- nokhwa (Windows only) ---
#[cfg(windows)]
use nokhwa::{
    query,
    pixel_format::RgbFormat,
    utils::{ApiBackend, CameraIndex, RequestedFormat, RequestedFormatType},
    Camera,
};

// ---- utils
#[inline] fn u64_be(x: u64) -> [u8; 8] { x.to_be_bytes() }
#[inline] fn u64_le(x: u64) -> [u8; 8] { x.to_le_bytes() }
#[inline] fn u32_le(x: u32) -> [u8; 4] { x.to_le_bytes() }
#[inline] fn round_up_32(x: usize) -> usize { (x + 31) & !31 }

const USB_DETECT_LABEL: &str = "VELVETKEY.info";
const MUX_MAGIC: &[u8] = b"MUXV1"; // plaintext marker just after 32B tag placeholder

#[inline]
fn i16s_to_le_bytes(samples: &[i16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(samples.len() * 2);
    for &s in samples {
        bytes.extend_from_slice(&s.to_le_bytes());
    }
    bytes
}

fn pick_cpal_host() -> cpal::Host {
    // Look at only the hosts compiled into this build
    let mut ids = cpal::available_hosts();

    // Prefer Pulse/PipeWire → JACK → ALSA → anything else
    ids.sort_by_key(|id| {
        let n = format!("{:?}", id).to_ascii_lowercase();
        match n.as_str() {
            "pulseaudio" | "pipewire" => 0,
            "jack"                     => 1,
            "alsa"                     => 2,
            _                          => 9,
        }
    });

    let chosen = ids
        .first()
        .cloned()
        .unwrap_or_else(|| cpal::default_host().id());

    cpal::host_from_id(chosen).unwrap_or_else(|_| cpal::default_host())
}

fn usb_key_detected() -> bool {
    cfg_if! {
        if #[cfg(unix)] {
            for base in ["/media", "/run/media"] {
                if let Ok(dir) = fs::read_dir(base) {
                    for user_dir in dir.flatten() {
                        if !user_dir.path().is_dir() { continue; }
                        if let Ok(mounts) = fs::read_dir(user_dir.path()) {
                            for mp in mounts.flatten() {
                                let marker = mp.path().join(USB_DETECT_LABEL);
                                if marker.is_file() { return true; }
                            }
                        }
                    }
                }
            }
            false
        } else if #[cfg(windows)] {
            for letter in b'A'..=b'Z' {
                let root = PathBuf::from(format!("{}:\\", letter as char));
                if root.exists() && root.join(USB_DETECT_LABEL).is_file() { return true; }
            }
            false
        } else {
            false
        }
    }
}

fn sigilbook_prog() -> String {
    let exe = if cfg!(windows) { "sigilbook.exe" } else { "sigilbook" };
    if let Ok(p) = std::env::var("SIGILBOOK_PROG") {
        return p;
    }
    let local = std::path::PathBuf::from(format!("./target/release/{exe}"));
    if local.exists() {
        return local.to_string_lossy().into_owned();
    }
    exe.to_string()
}

fn run_sigilbook(args: &[&str]) -> (bool, String) {
    let prog = sigilbook_prog();
    let out = Command::new(&prog)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    match out {
        Ok(o) => (o.status.success(), String::from_utf8_lossy(&o.stdout).to_string()),
        Err(e) => (false, format!("spawn error: {e}")),
    }
}

fn sigilbook_save(vault_path: &Path, password: &str) -> bool {
    let prog = sigilbook_prog();
    let mut child = match Command::new(&prog)
        .arg("save").arg(vault_path).arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    { Ok(c)=>c, Err(_)=>return false };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(password.as_bytes());
        let _ = stdin.write_all(b"\n");
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

fn sigilbook_get(vault_path: &Path) -> Option<String> {
    let prog = sigilbook_prog();
    let out = Command::new(&prog)
        .arg("get").arg(vault_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output().ok()?;
    if !out.status.success() { return None; }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() || s == "(not found)" { None } else { Some(s) }
}

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
    for _ in 0..n { s.push((33u8 + (next() % 94) as u8) as char); }
    s
}

fn salt_from_ts_nonce(ts_ns: u64, nonce12: &[u8; 12]) -> [u8; 32] {
    let mut inbuf = [0u8; 20];
    inbuf[..8].copy_from_slice(&u64_be(ts_ns));
    inbuf[8..20].copy_from_slice(nonce12);
    let mut out = [0u8; 32];
    let mut h = blake3::Hasher::new();
    h.update(&inbuf);
    h.finalize_xof().fill(&mut out);
    out
}

// ---------- preview helpers (video) ----------
fn yuyv_to_rgba(yuyv: &[u8], w: u32, h: u32) -> ColorImage {
    let (w, h) = (w as usize, h as usize);
    let mut rgba = vec![0u8; w*h*4];
    let clamp = |v: i32| -> u8 { v.max(0).min(255) as u8 };
    let mut i = 0;
    for y in 0..h {
        for x in (0..w).step_by(2) {
            let y0 = yuyv[i] as i32;
            let u  = yuyv[i+1] as i32 - 128;
            let y1 = yuyv[i+2] as i32;
            let v  = yuyv[i+3] as i32 - 128;
            i += 4;

            let r0 = clamp((298*(y0-16) + 409*v + 128) >> 8);
            let g0 = clamp((298*(y0-16) - 100*u - 208*v + 128) >> 8);
            let b0 = clamp((298*(y0-16) + 516*u + 128) >> 8);

            let r1 = clamp((298*(y1-16) + 409*v + 128) >> 8);
            let g1 = clamp((298*(y1-16) - 100*u - 208*v + 128) >> 8);
            let b1 = clamp((298*(y1-16) + 516*u + 128) >> 8);

            let idx0 = (y*w + x) * 4;
            let idx1 = (y*w + x + 1) * 4;
            rgba[idx0..idx0+4].copy_from_slice(&[r0,g0,b0,255]);
            rgba[idx1..idx1+4].copy_from_slice(&[r1,g1,b1,255]);
        }
    }
    ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba)
}

fn decode_mjpg_to_rgba(mjpg: &[u8]) -> Result<(ColorImage, u32, u32)> {
    let mut rdr = std::io::Cursor::new(mjpg);
    let dec = image::codecs::jpeg::JpegDecoder::new(&mut rdr)?;
    let (w, h) = dec.dimensions();
    let cty = dec.color_type();
    let mut buf = vec![0u8; dec.total_bytes() as usize];

    let mut rdr2 = std::io::Cursor::new(mjpg);
    let dec2 = image::codecs::jpeg::JpegDecoder::new(&mut rdr2)?;
    dec2.read_image(&mut buf)?;

    let img = match cty {
        image::ColorType::Rgb8 => {
            let mut rgba = Vec::with_capacity((w * h * 4) as usize);
            for chunk in buf.chunks_exact(3) {
                rgba.extend_from_slice(&[chunk[0], chunk[1], chunk[2], 255]);
            }
            ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba)
        }
        image::ColorType::L8 => {
            let mut rgba = Vec::with_capacity((w * h * 4) as usize);
            for &g in &buf { rgba.extend_from_slice(&[g, g, g, 255]); }
            ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba)
        }
        image::ColorType::Rgba8 => {
            ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &buf)
        }
        _ => {
            let dynimg = image::load_from_memory(mjpg)?;
            let rgba = dynimg.to_rgba8();
            ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba)
        }
    };
    Ok((img, w, h))
}

// ---------- device enumeration ----------
fn enumerate_cams() -> Vec<(String, String)> {
    cfg_if! {
        if #[cfg(unix)] {
            let mut out = Vec::new();
            for i in 0..=9 {
                let p = format!("/dev/video{}", i);
                let path = Path::new(&p);
                if !path.exists() { continue; }
                if let Ok(dev) = Device::with_path(&p) {
                    let card_name = dev.query_caps().map(|c| c.card).unwrap_or_else(|_| "(unknown)".into());
                    out.push((p, card_name));
                }
            }
            out
        } else if #[cfg(windows)] {
            let mut out = Vec::new();
            // Media Foundation via nokhwa
            let devices = query(ApiBackend::Auto).unwrap_or_default();
            for d in devices {
                let idx = match d.index() { CameraIndex::Index(i) => i, _ => 0 };
                let name = d.human_name().unwrap_or_else(|_| "(unknown)".into());
                out.push((format!("nokhwa://{}", idx), name));
            }
            out
        } else {
            Vec::new()
        }
    }
}

#[derive(Clone)]
struct MicInfo {
    name: String,
    sr: u32,
    channels: u16,
    sample_format: SampleFormat,
}

fn enumerate_mics() -> Vec<String> {
    let host = pick_cpal_host();
    let mut list = Vec::new();
    if let Ok(devs) = host.input_devices() {
        for dev in devs {
            let name = dev.name().unwrap_or_else(|_| "(unknown mic)".into());
            list.push(name);
        }
    }
    list
}

// ---------- runtime structs ----------
struct FrameMsg {
    w: u32,
    h: u32,
    fourcc: [u8;4],
    data: Vec<u8>, // MJPG or YUYV bytes
}

struct CamRuntime {
    devpath: String,
    fourcc: String,
    w: u32,
    h: u32,
    fps: u32,
    rx_preview: xchan::Receiver<FrameMsg>,
    latest_tex: Option<TextureHandle>,
}

struct MicRuntime {
    device_name: String,
    sr: u32,
    channels: u16,
    fmt: SampleFormat,
}

#[derive(Clone, Serialize, Deserialize)]
struct ComboCfg {
    id: String,
    name: String,
    cam: CamCfg,
    mic: MicCfg,
    mux_enabled: bool,
}
#[derive(Clone, Serialize, Deserialize)]
struct CamCfg {
    devpath: String,
    fourcc: String,
    resolution: String, // "WxH"
    fps: u32,
}
#[derive(Clone, Serialize, Deserialize)]
struct MicCfg {
    device_name: String,
    sample_rate: u32,
    channels: u16,
    format: String, // "i16"|"f32"|"u16"
}

#[derive(Default, Serialize, Deserialize)]
struct AppConfig {
    version: u32,
    combos: Vec<ComboCfg>,
}

fn config_path(out_dir: &Path) -> PathBuf {
    out_dir.join("config.json")
}

fn load_config(out_dir: &Path) -> AppConfig {
    let p = config_path(out_dir);
    if let Ok(b) = fs::read(&p) {
        if let Ok(cfg) = serde_json::from_slice::<AppConfig>(&b) { return cfg; }
    }
    AppConfig::default()
}

fn save_config(out_dir: &Path, cfg: &AppConfig) {
    let p = config_path(out_dir);
    let _ = fs::create_dir_all(out_dir);
    if let Ok(b) = serde_json::to_vec_pretty(cfg) { let _ = fs::write(p, b); }
}

struct RecorderCfg {
    out_dir: PathBuf,
    retention: Duration,
    seg_len: Duration,
    save_to_key: bool,
    session_pw: String,
}

struct SegmentCtx {
    out: File,
    path: PathBuf,
    header_bytes: [u8; 61],
    k_mac32: [u8; 32],
    cfg: SARXConfig,
    postmix: Vec<u8>,
    abs_off: u64,
    tag_pos: u64,
    end_at: Instant,
    save_to_key: bool,
    session_pw: String,
    prev_tag: [u8; 32], // rolling per-frame tag
}

fn start_segment_mux(
    session_pw: &str,
    out_dir: &Path,
    w: u32, h: u32,
    seg_len: Duration,
    save_to_key: bool,
) -> Result<SegmentCtx> {
    fs::create_dir_all(out_dir).ok();

    let timestamp_ns = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
    let mut nonce12 = [0u8; 12]; rand::thread_rng().fill_bytes(&mut nonce12);
    let salt32 = salt_from_ts_nonce(timestamp_ns, &nonce12);

    // Derive keys
    let pass_bytes = session_pw.as_bytes().len();
    let k_stream_len = round_up_32(pass_bytes).max(32);
    let okm_len = k_stream_len + 32;
    let mut okm = vec![0u8; okm_len];
    {
        use argon2::{Algorithm, Argon2, Params, Version};
        let params = Params::new(1 << 17, 3, 1, Some(okm_len)).unwrap();
        let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        a2.hash_password_into(session_pw.as_bytes(), &salt32, &mut okm)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    }
    let (k_stream, k_mac) = okm.split_at(k_stream_len);
    let mut k_mac32 = [0u8; 32]; k_mac32.copy_from_slice(&k_mac[..32]);

    // SARX config + postmix
    let cfg = generate_config_with_timestamp(session_pw, None, 0, timestamp_ns)?;
    let mut postmix = Vec::with_capacity(16 + k_stream_len + 12 + 8);
    postmix.extend_from_slice(b"SARX2DU-POST\0\0\0\0");
    postmix.extend_from_slice(k_stream);
    postmix.extend_from_slice(&nonce12);
    postmix.extend_from_slice(&u64_be(timestamp_ns));

    // Header
    let header = VaultHeader {
        salt32,
        timestamp_ns,
        nonce12,
        t_cost: 3,
        m_cost: 17,
        lanes: 1,
        kdf_id: 2,
    };
    let header_bytes = header.encode();

    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let seg_path = out_dir.join(format!("combo-{}x{}-{}.vault", w, h, stamp));
    let mut out = File::create(&seg_path).with_context(|| format!("create {}", seg_path.display()))?;
    out.write_all(&header_bytes)?;
    let tag_pos = out.seek(SeekFrom::Current(0))?;
    out.write_all(&[0u8; 32])?;
    // write mux magic (plaintext, MACed at finalize)
    out.write_all(MUX_MAGIC)?;

    okm.zeroize();

    Ok(SegmentCtx {
        out,
        path: seg_path,
        header_bytes,
        k_mac32,
        cfg,
        postmix,
        abs_off: 0,
        tag_pos,
        end_at: Instant::now() + seg_len,
        save_to_key,
        session_pw: session_pw.to_string(),
        prev_tag: [0u8; 32],
    })
}

/// Writes a mux record: plaintext header + per-frame rolling tag + encrypted payload
fn write_mux_record(
    s: &mut SegmentCtx,
    frame_type: u8,      // 0=video, 1=audio
    ts_ns: u64,
    seq: u64,
    payload: &[u8],
) -> Result<()> {
    // compute per-frame tag
    let mut mac = blake3::Hasher::new_keyed(&s.k_mac32);
    mac.update(b"SARX2DU-MUX-FRAME-v1");
    mac.update(&s.header_bytes);
    mac.update(&u64_le(ts_ns));
    mac.update(&u64_le(seq));
    mac.update(&u32_le(payload.len() as u32));
    mac.update(&[frame_type]);
    mac.update(&s.prev_tag);
    let mut tag = [0u8; 32];
    mac.finalize_xof().fill(&mut tag);

    // header (plaintext)
    s.out.write_all(&[frame_type])?;
    s.out.write_all(&u64_le(ts_ns))?;
    s.out.write_all(&u64_le(seq))?;
    s.out.write_all(&u32_le(payload.len() as u32))?;
    s.out.write_all(&tag)?;

    // ciphertext = payload XOR keystream
    let n = payload.len();
    let mut ks = vec![0u8; n];
    generate_stream(&s.cfg, Some(&s.postmix), s.abs_off, n, &mut ks)?;
    let mut ct = vec![0u8; n];
    for i in 0..n { ct[i] = payload[i] ^ ks[i]; }
    s.out.write_all(&ct)?;

    s.abs_off = s.abs_off.wrapping_add(n as u64);
    s.prev_tag = tag;
    Ok(())
}

fn finalize_segment(mut s: SegmentCtx) -> Result<()> {
    s.out.flush()?;
    // Everything after the 32B file tag placeholder is MACed: magic + record headers + ciphertext
    let ct_start = (s.header_bytes.len() + 32) as u64;
    let file_end = s.out.seek(SeekFrom::Current(0))?;
    let clen = file_end.saturating_sub(ct_start);

    let mut mac = blake3::Hasher::new_keyed(&s.k_mac32);
    mac.update(b"SARX2DU-MAC-v1");
    mac.update(&s.header_bytes);
    mac.update(&(clen as u64).to_le_bytes());

    let mut rf = File::open(&s.path)?;
    rf.seek(SeekFrom::Start(ct_start))?;
    let mut buf = vec![0u8; 16 * 1024 * 1024];
    let mut left = clen as usize;
    while left > 0 {
        let n = left.min(buf.len());
        rf.read_exact(&mut buf[..n])?;
        mac.update(&buf[..n]);
        left -= n;
    }

    let mut tag = [0u8; 32];
    mac.finalize_xof().fill(&mut tag);

    s.out.seek(SeekFrom::Start(s.tag_pos))?;
    s.out.write_all(&tag)?;
    s.out.flush()?;
    let _ = s.out.sync_all();

    if s.save_to_key {
        if let Ok(abs) = std::fs::canonicalize(&s.path) {
            let _ = sigilbook_save(&abs, &s.session_pw);
        }
    }
    Ok(())
}

fn cleanup_old_segments(dir: &Path, retention: Duration) {
    let now = SystemTime::now();
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) != Some("vault") { continue; }
            if let Ok(m) = e.metadata() {
                if let Ok(mt) = m.modified() {
                    if now.duration_since(mt).unwrap_or(Duration::ZERO) > retention {
                        let _ = fs::remove_file(&p);
                    }
                }
            }
        }
    }
}

// ---------- AV Combo runtime ----------
enum AvMsg {
    Video { ts_ns: u64, w: u32, h: u32, fourcc: [u8;4], bytes: Vec<u8> },
    Audio { ts_ns: u64, bytes: Vec<u8> }, // s16le, interleaved, stereo if possible
}

struct AvWorkerHandle {
    stop: Arc<Mutex<bool>>,
    joins: Vec<thread::JoinHandle<()>>,
}

struct AvCombo {
    id: String,
    name: String,
    cam: CamRuntime,
    mic: MicRuntime,
    mux_enabled: bool,
    worker: Option<AvWorkerHandle>,
}

// ---------- Viewer ----------
fn spawn_ffplay_video_mjpeg() -> Option<std::process::ChildStdin> {
    let args: Vec<String> = vec![
        "-loglevel".into(), "quiet".into(),
        "-fflags".into(), "+nobuffer".into(),
        "-f".into(), "mjpeg".into(),
        "-i".into(), "-".into(),
        "-window_title".into(), "SARX Video".into(),
    ];
    Command::new("ffplay").args(&args).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().ok()?.stdin.take()
}

fn spawn_ffplay_audio_48k2() -> Option<std::process::ChildStdin> {
    let args: Vec<String> = vec![
        "-loglevel".into(), "quiet".into(),
        "-fflags".into(), "+nobuffer".into(),
        "-f".into(), "s16le".into(),
        "-ar".into(), "48000".into(),
        "-ac".into(), "2".into(),
        "-i".into(), "-".into(),
        "-window_title".into(), "SARX Audio".into(),
    ];
    Command::new("ffplay").args(&args).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().ok()?.stdin.take()
}

/// Decrypts a .vault; if MUXV1 is present after tag, demux A/V; else treat as video-only mjpeg.
fn view_vault_file(path: &Path, pw_opt: Option<String>) -> anyhow::Result<()> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hdr = [0u8; 61]; f.read_exact(&mut hdr)?;
    let header = VaultHeader::decode(&hdr).context("decode header")?;
    let mut tag_file = [0u8; 32]; f.read_exact(&mut tag_file)?;

    let file_size = f.metadata()?.len();
    if file_size < (61 + 32) as u64 { anyhow::bail!("invalid vault"); }
    let clen = (file_size as usize) - (61 + 32);
    let ct_start = (61 + 32) as u64;

    let pw = if let Some(p) = pw_opt { p } else if let Some(p) = sigilbook_get(path) { p } else { anyhow::bail!("password not found"); };

    let pass_bytes = pw.as_bytes().len();
    let k_stream_len = ((pass_bytes + 31) & !31).max(32);
    let okm_len = k_stream_len + 32;
    let mut okm = vec![0u8; okm_len];
    {
        use argon2::{Algorithm, Argon2, Params, Version};
        let mem_kib: u32 = 1u32 << header.m_cost;
        let params = Params::new(mem_kib, header.t_cost.into(), header.lanes.into(), Some(okm_len)).unwrap();
        let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        a2.hash_password_into(pw.as_bytes(), &header.salt32, &mut okm)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    }
    let (k_stream, k_mac) = okm.split_at(k_stream_len);
    let mut k_mac32 = [0u8; 32]; k_mac32.copy_from_slice(&k_mac[..32]);

    let mut mac = blake3::Hasher::new_keyed(&k_mac32);
    mac.update(b"SARX2DU-MAC-v1");
    mac.update(&hdr);
    mac.update(&(clen as u64).to_le_bytes());
    f.seek(SeekFrom::Start(ct_start))?;
    let mut tmp = vec![0u8; 16 * 1024 * 1024];
    let mut left = clen;
    while left > 0 {
        let n = left.min(tmp.len());
        f.read_exact(&mut tmp[..n])?;
        mac.update(&tmp[..n]);
        left -= n;
    }
    let mut tag_calc = [0u8; 32];
    mac.finalize_xof().fill(&mut tag_calc);
    if tag_calc != tag_file { anyhow::bail!("MAC mismatch"); }

    // detect mux
    f.seek(SeekFrom::Start(ct_start))?;
    let mut magic = [0u8; 5];
    f.read_exact(&mut magic)?;
    let muxed = &magic == MUX_MAGIC;

    // keystream cfg
    let cfg = generate_config_with_timestamp(&pw, None, 0, header.timestamp_ns)?;
    let mut postmix = Vec::with_capacity(16 + k_stream_len + 12 + 8);
    postmix.extend_from_slice(b"SARX2DU-POST\0\0\0\0");
    postmix.extend_from_slice(k_stream);
    postmix.extend_from_slice(&header.nonce12);
    postmix.extend_from_slice(&header.timestamp_ns.to_be_bytes());

    if !muxed {
        // legacy: whole body is encrypted mjpeg
        let mut viewer = spawn_ffplay_video_mjpeg().ok_or_else(|| anyhow::anyhow!("ffplay video not available"))?;
        f.seek(SeekFrom::Start(ct_start))?;
        let mut abs_off = 0u64;
        loop {
            let n = f.read(&mut tmp)?;
            if n == 0 { break; }
            let mut ks = vec![0u8; n];
            generate_stream(&cfg, Some(&postmix), abs_off, n, &mut ks)?;
            for i in 0..n { tmp[i] ^= ks[i]; }
            use std::io::Write;
            viewer.write_all(&tmp[..n])?;
            abs_off = abs_off.wrapping_add(n as u64);
        }
        okm.zeroize();
        return Ok(());
    }

    // muxed: demux loop
    let mut vid_pipe = spawn_ffplay_video_mjpeg();
    let mut aud_pipe = spawn_ffplay_audio_48k2();

    let mut abs_off = 0u64; // keystream offset only over payload bytes
    loop {
        let mut header_buf = [0u8; 1 + 8 + 8 + 4 + 32];
        let n = f.read(&mut header_buf)?;
        if n == 0 { break; }
        if n != header_buf.len() { anyhow::bail!("truncated record header"); }

        let frame_type = header_buf[0];
        let _ts_ns = u64::from_le_bytes(header_buf[1..9].try_into().unwrap());
        let _seq = u64::from_le_bytes(header_buf[9..17].try_into().unwrap());
        let payload_len = u32::from_le_bytes(header_buf[17..21].try_into().unwrap()) as usize;
        // let _frame_tag = &header_buf[21..53];

        let mut ct = vec![0u8; payload_len];
        f.read_exact(&mut ct)?;
        let mut ks = vec![0u8; payload_len];
        generate_stream(&cfg, Some(&postmix), abs_off, payload_len, &mut ks)?;
        for i in 0..payload_len { ct[i] ^= ks[i]; }
        abs_off = abs_off.wrapping_add(payload_len as u64);

        match frame_type {
            0 => { if let Some(ref mut vp) = vid_pipe { let _ = vp.write_all(&ct); } }
            1 => { if let Some(ref mut ap) = aud_pipe { let _ = ap.write_all(&ct); } }
            _ => {}
        }
    }
    okm.zeroize();
    Ok(())
}

// ---------- App / GUI ----------
struct App {
    // global settings
    out_dir: PathBuf,
    retention_min: u32,
    segment_sec: u32,
    save_to_key: bool,
    session_pw: String,

    // usb
    usb_detected: bool,
    last_usb_poll: Instant,

    // combos
    combos: Vec<AvCombo>,
    cfg_cache: AppConfig,

    // add-combo modal
    show_add_combo: bool,
    sel_cam: String,
    sel_mic: String,
    avail_cams: Vec<(String, String)>,
    avail_mics: Vec<String>,  
    new_mux_enabled: bool,

    // right-panel viewer
    status: String,
    selected_file: Option<PathBuf>,
    pw_prompt_for: Option<PathBuf>,
    pw_input: String,
    app_tx: xchan::Sender<String>,
    app_rx: xchan::Receiver<String>,
}

impl Default for App {
    fn default() -> Self {
        let (tx, rx) = xchan::unbounded();
        let out_dir_default = PathBuf::from("./encrypted_cam");
        let cfg = load_config(&out_dir_default);

        let avail_cams = enumerate_cams();
        let avail_mics = enumerate_mics();
        
        // start with config combos (stopped)
        let mut combos: Vec<AvCombo> = Vec::new();
        for c in &cfg.combos {
            let (w, h) = parse_res(&c.cam.resolution).unwrap_or((640, 480));
            let (_txp, rxp) = xchan::unbounded::<FrameMsg>();
            let cam_rt = CamRuntime {
                devpath: c.cam.devpath.clone(),
                fourcc: c.cam.fourcc.clone(),
                w, h, fps: c.cam.fps,
                rx_preview: rxp,
                latest_tex: None,
            };
            let mic_rt = MicRuntime {
                device_name: c.mic.device_name.clone(),
                sr: c.mic.sample_rate,
                channels: c.mic.channels,
                fmt: match c.mic.format.as_str() { "i16" => SampleFormat::I16, "u16" => SampleFormat::U16, _ => SampleFormat::F32 },
            };
            combos.push(AvCombo {
                id: c.id.clone(),
                name: c.name.clone(),
                cam: cam_rt,
                mic: mic_rt,
                mux_enabled: c.mux_enabled,
                worker: None,
            });
        }

        Self {
            out_dir: PathBuf::from("./encrypted_cam"),
            retention_min: 5,
            segment_sec: 5,
            save_to_key: true,
            session_pw: make_password_ascii(64),

            usb_detected: usb_key_detected(),
            last_usb_poll: Instant::now(),

            combos,
            cfg_cache: cfg,

            show_add_combo: false,
            sel_cam: avail_cams.get(0).map(|(p, _)| p.clone()).unwrap_or_default(),
            sel_mic: avail_mics.get(0).cloned().unwrap_or_default(),
            avail_cams,
            avail_mics,
            new_mux_enabled: true,

            status: "Ready.".into(),
            selected_file: None,
            pw_prompt_for: None,
            pw_input: String::new(),
            app_tx: tx,
            app_rx: rx,
        }
    }
}

fn parse_res(s: &str) -> Option<(u32,u32)> {
    let mut it = s.split('x');
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.last_usb_poll.elapsed() >= Duration::from_millis(1000) {
            self.usb_detected = usb_key_detected();
            self.last_usb_poll = Instant::now();
        }

        // ===== Top bar =====
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label("Out dir:");
                let mut s = self.out_dir.display().to_string();
                if ui.text_edit_singleline(&mut s).lost_focus() {
                    self.out_dir = PathBuf::from(s.clone());
                }
                ui.separator();
                ui.label("Keep (min):");
                ui.add(egui::DragValue::new(&mut self.retention_min).clamp_range(1..=1440));
                ui.separator();
                ui.label("Segment (s):");
                ui.add(egui::DragValue::new(&mut self.segment_sec).clamp_range(2..=60));
                ui.separator();

                // USB controls
                let usb_label = if self.usb_detected { "USB: Detected ✅" } else { "USB: Not detected ⛔" };
                ui.label(usb_label);
                if ui.button("Detect").clicked() {
                    let (_ok, out) = run_sigilbook(&["detect"]);
                    self.status = if out.trim().is_empty() { "Ran sigilbook detect.".into() } else { out };
                    self.usb_detected = usb_key_detected();
                }
                if ui.add_enabled(self.usb_detected, egui::Button::new("Init")).clicked() {
                    let (ok, out) = run_sigilbook(&["init"]);
                    self.status = if ok { format!("Init ok. {}", out) } else { format!("Init failed. {}", out) };
                    self.usb_detected = usb_key_detected();
                }
                if ui.add_enabled(self.usb_detected, egui::Button::new("Rekey")).clicked() {
                    let (ok, out) = run_sigilbook(&["rekey"]);
                    self.status = if ok { format!("Rekey ok. {}", out) } else { format!("Rekey failed. {}", out) };
                }
                if ui.button("Forget").clicked() {
                    let (_ok, out) = run_sigilbook(&["forget"]);
                    self.status = if out.trim().is_empty() { "Forgot active USB.".into() } else { out };
                    self.usb_detected = usb_key_detected();
                }

                ui.separator();
                ui.add_enabled(self.usb_detected, egui::Checkbox::new(&mut self.save_to_key, "Save pw to USB"));
            });

            ui.horizontal_wrapped(|ui| {
                ui.label("Session password:");
                let mut pw = self.session_pw.clone();
                if ui.add(egui::TextEdit::singleline(&mut pw).desired_width(420.0)).lost_focus() {
                    self.session_pw = pw;
                }
                if ui.button("Randomize").clicked() {
                    self.session_pw = make_password_ascii(64);
                }
                ui.separator();
                if ui.button("+ Add cam/mic combo").clicked() {
                    self.avail_cams = enumerate_cams();
                    if self.avail_mics.is_empty() { self.avail_mics = enumerate_mics(); }
                    self.sel_cam = self.avail_cams.get(0).map(|(p, _)| p.clone()).unwrap_or_default();
                    self.sel_mic = self.avail_mics.get(0).cloned().unwrap_or_default();
                    self.show_add_combo = true;
                }
            });
        });

        // ===== Add combo modal =====
        if self.show_add_combo {
            egui::Window::new("Add cam/mic combo")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Camera:");
                        egui::ComboBox::from_id_source("cam_dd")
                            .selected_text(&self.sel_cam)
                            .show_ui(ui, |ui| {
                                // cameras: (path, name)
                                for (path, name) in &self.avail_cams {
                                    ui.selectable_value(
                                        &mut self.sel_cam,
                                        path.clone(),
                                        format!("{} ({})", name, path),
                                    );
                                }
                            });
                    });
                    ui.horizontal(|ui| {
                        ui.label("Mic:");
                        egui::ComboBox::from_id_source("mic_dd")
                            .selected_text(&self.sel_mic)
                            .show_ui(ui, |ui| {
                                // mics: just names
                                for m in &self.avail_mics {
                                    ui.selectable_value(
                                        &mut self.sel_mic,
                                        m.clone(),
                                        m,
                                    );
                                }
                            });
                    });
                    ui.checkbox(&mut self.new_mux_enabled, "Mux audio + video into one .vault (recommended)");
                    if ui.button("Create").clicked() {
                        // probe cam format
                        let dev = Device::with_path(&self.sel_cam)
                            .expect("Could not open camera device");
                        let (fourcc, w, h, fps) = detect_format(&dev);
                        let (_txp, rxp) = xchan::unbounded::<FrameMsg>();
                        let cam_rt = CamRuntime {
                            devpath: self.sel_cam.clone(),
                            fourcc: fourcc.clone(),
                            w, h, fps,
                            rx_preview: rxp,
                            latest_tex: None,
                        };
                        // mic pick (names only; runtime will choose exact config)
                        let mic_name = self.sel_mic.clone();
                        let mic_rt = MicRuntime {
                            device_name: mic_name.clone(),
                            sr: 48_000,
                            channels: 2,
                            fmt: SampleFormat::I16,
                        };
                        let id = format!("combo-{}", self.combos.len()+1);
                        let name = format!("{} / {}", self.sel_cam.clone(), self.sel_mic.clone());
                        self.combos.push(AvCombo {
                            id: id.clone(),
                            name: name.clone(),
                            cam: cam_rt,
                            mic: mic_rt,
                            mux_enabled: self.new_mux_enabled,
                            worker: None,
                        });
                        // persist
                        self.cfg_cache.version = 1;
                        let res_str = format!("{}x{}", w, h);
                        let fmt_str = "i16".to_string();
                        self.cfg_cache.combos.push(ComboCfg {
                            id, name,
                            cam: CamCfg { devpath: self.sel_cam.clone(), fourcc, resolution: res_str, fps },
                            mic: MicCfg { device_name: mic_name, sample_rate: 48_000, channels: 2, format: fmt_str },
                            mux_enabled: self.new_mux_enabled,
                        });
                        save_config(&self.out_dir, &self.cfg_cache);
                        self.show_add_combo = false;
                    }
                });
        }

        // ===== Right panel: Encrypted Files =====
        egui::SidePanel::right("right_files").min_width(360.0).show(ctx, |ui| {
            ui.heading("Encrypted Segments");
            ui.label(self.out_dir.display().to_string());
            ui.add_space(6.0);

            let mut files: Vec<PathBuf> = Vec::new();
            if let Ok(rd) = fs::read_dir(&self.out_dir) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.extension().and_then(|s| s.to_str()) == Some("vault") {
                        files.push(p);
                    }
                }
            }
            files.sort_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok());
            files.reverse();

            egui::ScrollArea::vertical().show(ui, |ui| {
                for p in files.iter() {
                    let label = p.file_name().and_then(|s| s.to_str()).unwrap_or("(?)").to_string();
                    ui.horizontal(|ui| {
                        if ui.selectable_label(self.selected_file.as_ref() == Some(p), label).clicked() {
                            self.selected_file = Some(p.clone());
                        }
                        if ui.button("▶ View").clicked() {
                            let path = p.clone();
                            let status_path = path.display().to_string();
                            let status_path_ui = status_path.clone();
                            if let Some(pw) = sigilbook_get(&path) {
                                let tx = self.app_tx.clone();
                                std::thread::spawn(move || {
                                    let res = view_vault_file(&path, Some(pw));
                                    let _ = tx.send(match res {
                                        Ok(()) => format!("Done viewing {status_path}"),
                                        Err(e)  => format!("❌ {}", e),
                                    });
                                });
                                self.status = format!("Viewing {}...", status_path_ui);
                            } else {
                                self.pw_prompt_for = Some(path);
                                self.pw_input.clear();
                            }
                        }
                        if ui.button("🗑 Delete").clicked() {
                            let _ = std::fs::remove_file(p);
                        }
                    });
                }
            });

            ui.separator();
            ui.label(&self.status);
        });

        // ===== Center: combo tiles =====
        egui::CentralPanel::default().show(ctx, |ui| {
            let cols = (self.combos.len() as f32).sqrt().ceil().max(1.0) as usize;
            let tile_w = ui.available_width() / cols as f32 - 8.0;

            for (i, combo) in self.combos.iter_mut().enumerate() {
                if i % cols == 0 { ui.horizontal(|_|{}); }
                ui.vertical(|ui| {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(format!("{} • {}x{}@{} • {}", combo.cam.devpath, combo.cam.w, combo.cam.h, combo.cam.fps, combo.cam.fourcc)).strong());
                            ui.separator();
                            ui.label(format!("Mic: {}", combo.mic.device_name));
                        });

                        // LIVE / STOP
                        let live = combo.worker.is_some();
                        if !live {
                            if ui.button("🔴 Live").clicked() {
                                // start worker threads
                                let (tx_preview, rx_preview) = xchan::unbounded::<FrameMsg>();
                                combo.cam.rx_preview = rx_preview;

                                let stop = Arc::new(Mutex::new(false));
                                let _out_dir = self.out_dir.clone();
                                let seg_len = Duration::from_secs(self.segment_sec as u64);
                                let retention = Duration::from_secs((self.retention_min as u64) * 60);
                                let save_to_key = self.save_to_key;
                                let session_pw = self.session_pw.clone();

                                let (mux_tx, mux_rx) = xchan::unbounded::<AvMsg>();
                                let mux_tx_cam = mux_tx.clone(); 
                                
                                // camera thread
                                // camera thread
                                let devpath_cam = combo.cam.devpath.clone();
                                let stop_cam = Arc::clone(&stop);
                                
                                let join_cam; // <<== Declare it *before* the cfg_if!

                                let sel_cam = self.sel_cam.clone();
                                let devpath_cam = combo.cam.devpath.clone();
                                let stop_cam = Arc::clone(&stop);
                                let tx_preview = tx_preview.clone();
                                let mux_tx_cam = mux_tx_cam.clone();

                                cfg_if! {
                                    if #[cfg(unix)] {
                                        join_cam = thread::spawn(move || {
                                            let dev = Device::with_path(&sel_cam)
                                                .expect("Could not open camera device");
                                            let (fourcc, w, h, fps) = detect_format(&dev);

                                            let fmt = dev.format().unwrap_or_else(|_| v4l::Format::new(640, 480, v4l::FourCC::new(b"YUYV")));
                                            let w = fmt.width;
                                            let h = fmt.height;
                                            let fourcc = fmt.fourcc;
                                            let mut fourcc4 = [0u8; 4];
                                            let fourcc_s = fourcc.str().unwrap_or("RAW").as_bytes();
                                            for i in 0..fourcc_s.len().min(4) {
                                                fourcc4[i] = fourcc_s[i];
                                            }
                                            let mut stream = match V4lMmapStream::with_buffers(&dev, V4lBufType::VideoCapture, 4) {
                                                Ok(s)=>s, Err(e)=>{ eprintln!("[{}] start stream: {e}", devpath_cam); return; }
                                            };
                                            let mut last_preview = Instant::now();

                                            while !*stop_cam.lock() {
                                                let (buf, _meta) = match stream.next() { Ok(x)=>x, Err(_)=>continue };
                                                if buf.is_empty() { continue; }
                                                let _ = mux_tx_cam.send(AvMsg::Video {
                                                    ts_ns: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
                                                    w, h, fourcc: fourcc4, bytes: buf.to_vec()
                                                });
                                                if last_preview.elapsed().as_millis() >= 100 {
                                                    let _ = tx_preview.send(FrameMsg{ w, h, fourcc: fourcc4, data: buf.to_vec() });
                                                    last_preview = Instant::now();
                                                }
                                            }
                                        });
                                    } else if #[cfg(windows)] {
                                        let sel_cam = self.sel_cam.clone();
                                        let devpath_cam = combo.cam.devpath.clone();
                                        let stop_cam = Arc::clone(&stop);
                                        let tx_preview = tx_preview.clone();
                                        let mux_tx_cam = mux_tx_cam.clone();

                                        let (fourcc, w, h, fps) = detect_format_windows(&sel_cam);
                                        join_cam = thread::spawn(move || {
                                            // devpath is "nokhwa://<index>"
                                            let idx: usize = devpath_cam.trim_start_matches("nokhwa://").parse().unwrap_or(0);
                                            let mut cam = match Camera::new(
                                                CameraIndex::Index(idx),
                                                RequestedFormat::new::<RgbFormat>(RequestedFormatType::None),
                                            ) {
                                                Ok(c) => c,
                                                Err(e) => { eprintln!("[nokhwa {}] open: {e}", idx); return; }
                                            };

                                            let w = 640u32; let h = 480u32; let fps = 30u32;
                                            let _ = cam.set_resolution(w as u32, h as u32);
                                            let mut last_preview = Instant::now();

                                            while !*stop_cam.lock() {
                                                let frame = match cam.frame() {
                                                    Ok(f) => f,
                                                    Err(_) => continue,
                                                };
                                                let buf = frame.buffer().to_vec();
                                                let mut mjpeg = Vec::with_capacity((w*h/3) as usize);
                                                {
                                                    let mut enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut mjpeg, 80);
                                                    if let Err(e) = enc.encode(&buf, w, h, image::ColorType::Rgb8) {
                                                        eprintln!("jpeg encode: {e}");
                                                        continue;
                                                    }
                                                }
                                                let fourcc4 = *b"MJPG";
                                                let _ = mux_tx_cam.send(AvMsg::Video {
                                                    ts_ns: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
                                                    w, h, fourcc: fourcc4, bytes: mjpeg.clone()
                                                });
                                                if last_preview.elapsed().as_millis() >= 100 {
                                                    let _ = tx_preview.send(FrameMsg { w, h, fourcc: fourcc4, data: mjpeg });
                                                    last_preview = Instant::now();
                                                }
                                            }
                                        });
                                    } else {
                                        join_cam = thread::spawn(|| {});
                                    }
                                }

                                // audio stream (CPAL)
                                let host = pick_cpal_host();
                                let input_dev = host.input_devices().ok()
                                    .and_then(|mut it| it.find(|d| d.name().ok().as_deref() == Some(&combo.mic.device_name)));
                                let mut audio_stream_opt = None;
                                if let Some(dev) = input_dev {
                                    // choose config: prefer 48k within range; fall back to default
                                    let mut chosen: Option<(StreamConfig, SampleFormat)> = None;
                                    if let Ok(ranges) = dev.supported_input_configs() {
                                        for range in ranges {
                                            let fmt = range.sample_format();
                                            let chans = range.channels();
                                            let min = range.min_sample_rate().0;
                                            let max = range.max_sample_rate().0;
                                            if chans >= 1 && min <= 48_000 && max >= 48_000 {
                                                let sc = range.with_sample_rate(cpal::SampleRate(48_000));
                                                chosen = Some((sc.config(), sc.sample_format()));
                                                if fmt == SampleFormat::I16 { break; } // prefer native i16
                                            }
                                        }
                                    }
                                    if chosen.is_none() {
                                        if let Ok(def_cfg) = dev.default_input_config() {
                                            chosen = Some((def_cfg.config(), def_cfg.sample_format()));
                                        }
                                    }
                                    if let Some((cfg, fmt)) = chosen {
                                        let chans = cfg.channels as usize;
                                        let mic_stop_i16 = Arc::clone(&stop);
                                        let mic_stop_f32 = Arc::clone(&stop);
                                        let mic_stop_u16 = Arc::clone(&stop);

                                        let tx_i16 = mux_tx.clone();
                                        let tx_f32 = mux_tx.clone();
                                        let tx_u16 = mux_tx.clone();
                                            
                                        let build_i16 = || {
                                            dev.build_input_stream(
                                                &cfg,
                                                move |data: &[i16], _| {
                                                    if *mic_stop_i16.lock() { return; }
                                                    let frames = data.len() / chans;
                                                    if frames == 0 { return; }
                                                    let mut out: Vec<i16> = Vec::with_capacity(frames * 2);
                                                    if chans == 1 { for &s in data { out.push(s); out.push(s); } }
                                                    else { for f in 0..frames { out.push(data[f*chans]); out.push(data[f*chans+1]); } }
                                                    let bytes = i16s_to_le_bytes(&out);
                                                    let _ = tx_i16.send(AvMsg::Audio {
                                                        ts_ns: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
                                                        bytes
                                                    });
                                                },
                                                move |err| eprintln!("audio error: {err}"),
                                                None,
                                            )
                                        };

                                        let build_f32 = || {
                                            dev.build_input_stream(
                                                &cfg,
                                                move |data: &[f32], _| {
                                                    if *mic_stop_f32.lock() { return; }
                                                    let frames = data.len() / chans;
                                                    if frames == 0 { return; }
                                                    let mut out: Vec<i16> = Vec::with_capacity(frames * 2);
                                                    let to_i16 = |x: f32| (x.clamp(-1.0, 1.0) * i16::MAX as f32) as i16;
                                                    if chans == 1 { for &s in data { let v = to_i16(s); out.push(v); out.push(v); } }
                                                    else { for f in 0..frames { out.push(to_i16(data[f*chans])); out.push(to_i16(data[f*chans+1])); } }
                                                    let bytes = i16s_to_le_bytes(&out);
                                                    let _ = tx_f32.send(AvMsg::Audio {
                                                        ts_ns: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
                                                        bytes
                                                    });
                                                },
                                                move |err| eprintln!("audio error: {err}"),
                                                None,
                                            )
                                        };

                                        let build_u16 = || {
                                            dev.build_input_stream(
                                                &cfg,
                                                move |data: &[u16], _| {
                                                    if *mic_stop_u16.lock() { return; }
                                                    let frames = data.len() / chans;
                                                    if frames == 0 { return; }
                                                    let mut out: Vec<i16> = Vec::with_capacity(frames * 2);
                                                    let to_i16 = |x: u16| (x as i32 - 32768) as i16;
                                                    if chans == 1 { for &s in data { let v = to_i16(s); out.push(v); out.push(v); } }
                                                    else { for f in 0..frames { out.push(to_i16(data[f*chans])); out.push(to_i16(data[f*chans+1])); } }
                                                    let bytes = i16s_to_le_bytes(&out);
                                                    let _ = tx_u16.send(AvMsg::Audio {
                                                        ts_ns: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
                                                        bytes
                                                    });
                                                },
                                                move |err| eprintln!("audio error: {err}"),
                                                None,
                                            )
                                        };

                                        let stream_res = match fmt {
                                            SampleFormat::I16 => build_i16(),
                                            SampleFormat::F32 => build_f32(),
                                            SampleFormat::U16 => build_u16(),
                                            _ => build_i16(),
                                        };
                                        if let Ok(s) = stream_res {
                                            let _ = s.play();
                                            audio_stream_opt = Some(s);
                                        }
                                    }
                                }

                                // mux writer thread
                                let stop_mux = Arc::clone(&stop);
                                let out_dir2 = self.out_dir.clone();
                                let save_to_key2 = save_to_key;
                                let session_pw2 = session_pw.clone();
                                let retention2 = retention;
                                let seg_len2 = seg_len;
                                let join_mux = thread::spawn(move || {
                                    // estimate w/h from first video
                                    let mut w_est = 640u32; let mut h_est = 480u32;
                                    let mut seq_v: u64 = 0;
                                    let mut seq_a: u64 = 0;
                                    let mut seg_opt = Some(match start_segment_mux(&session_pw2, &out_dir2, w_est, h_est, seg_len2, save_to_key2) {
                                        Ok(s)=>s, Err(e)=>{ eprintln!("start_segment_mux: {e}"); return; }
                                    });

                                    loop {
                                        if *stop_mux.lock() { break; }
                                        match mux_rx.recv_timeout(Duration::from_millis(50)) {
                                            Ok(AvMsg::Video { ts_ns, w, h, fourcc: _fcc, bytes }) => {
                                                w_est = w; h_est = h;
                                                if let Some(ref mut seg) = seg_opt {
                                                    let _ = write_mux_record(seg, 0, ts_ns, seq_v, &bytes);
                                                }
                                                seq_v = seq_v.wrapping_add(1);
                                            }
                                            Ok(AvMsg::Audio { ts_ns, bytes }) => {
                                                if let Some(ref mut seg) = seg_opt {
                                                    let _ = write_mux_record(seg, 1, ts_ns, seq_a, &bytes);
                                                }
                                                seq_a = seq_a.wrapping_add(1);
                                            }
                                            Err(_) => {}
                                        }

                                        if let Some(ref seg) = seg_opt {
                                            if Instant::now() >= seg.end_at {
                                                if let Some(done) = seg_opt.take() {
                                                    if let Err(e) = finalize_segment(done) { eprintln!("finalize_segment: {e}"); }
                                                }
                                                cleanup_old_segments(&out_dir2, retention2);
                                                seg_opt = Some(match start_segment_mux(&session_pw2, &out_dir2, w_est, h_est, seg_len2, save_to_key2) {
                                                    Ok(s)=>s, Err(e)=>{ eprintln!("start_segment_mux: {e}"); break; }
                                                });
                                                seq_v = 0; seq_a = 0;
                                            }
                                        }
                                    }

                                    if let Some(done) = seg_opt.take() {
                                        let _ = finalize_segment(done);
                                    }
                                });

                                combo.worker = Some(AvWorkerHandle {
                                    stop, joins: vec![join_cam, join_mux]
                                });
                            }
                        } else {
                            if ui.button("⏹ Stop").clicked() {
                                if let Some(mut w) = combo.worker.take() {
                                    *w.stop.lock() = true;
                                    for j in w.joins.drain(..) { let _ = j.join(); }
                                }
                            }
                        }

                        // preview frame update
                        if let Ok(msg) = combo.cam.rx_preview.try_recv() {
                            let fourcc = std::str::from_utf8(&msg.fourcc).unwrap_or("RAW").trim_matches(char::from(0)).to_string();
                            let img = if fourcc == "MJPG" {
                                decode_mjpg_to_rgba(&msg.data).ok().map(|(im,_,_)| im)
                            } else {
                                Some(yuyv_to_rgba(&msg.data, msg.w, msg.h))
                            };
                            if let Some(ci) = img {
                                let tex = combo.cam.latest_tex.get_or_insert_with(|| {
                                    ui.ctx().load_texture(format!("camtex-{}", combo.cam.devpath), ci.clone(), egui::TextureOptions::LINEAR)
                                });
                                tex.set(ci, egui::TextureOptions::LINEAR);
                            }
                        }
                        if let Some(tex) = &combo.cam.latest_tex {
                            let ratio = tex.size()[0] as f32 / tex.size()[1] as f32;
                            let desired = Vec2::new(tile_w, tile_w/ratio);
                            ui.add(egui::Image::new((tex.id(), desired)));
                        } else {
                            ui.allocate_space(Vec2::new(tile_w, tile_w*0.75));
                        }
                    });
                });
            }
        });

        // ===== PW prompt modal =====
        if let Some(path) = self.pw_prompt_for.clone() {
            egui::Window::new("Enter password to view")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(path.display().to_string());
                    ui.add(egui::TextEdit::singleline(&mut self.pw_input).password(true).desired_width(320.0));
                    ui.horizontal(|ui| {
                        if ui.button("View").clicked() {
                            let pw = self.pw_input.clone();
                            let path2 = path.clone();
                            let status_path = path.display().to_string();
                            let status_path_ui = status_path.clone();
                            let tx = self.app_tx.clone();
                            std::thread::spawn(move || {
                                let res = view_vault_file(&path2, Some(pw));
                                let _ = tx.send(match res {
                                    Ok(()) => format!("Done viewing {status_path}"),
                                    Err(e)  => format!("❌ {}", e),
                                });
                            });
                            self.status = format!("Viewing {}...", status_path_ui);
                            self.pw_prompt_for = None;
                        }
                    });
                });
        }
    }
}

#[cfg(unix)]
fn detect_format(dev: &Device) -> (String, u32, u32, u32) {
    let fmt = dev.format().unwrap_or_else(|_| v4l::Format::new(640, 480, v4l::FourCC::new(b"YUYV")));
    let fourcc = fmt.fourcc.str().unwrap_or("RAW").to_string();
    let w = fmt.width; let h = fmt.height;
    let fps: u32 = dev.params().ok().map(|p| {
        let num = p.interval.numerator as f32;
        let den = p.interval.denominator as f32;
        if num > 0.0 { (den / num).round().max(1.0) as u32 } else { 30 }
    }).unwrap_or(30);
    (fourcc, w, h, fps)
}

#[cfg(windows)]
fn detect_format_windows(_devpath: &str) -> (String, u32, u32, u32) {
    // We'll request MJPEG @ 640x480@30 and encode to JPEG if needed.
    ("MJPG".into(), 640, 480, 30)
}

fn main() -> eframe::Result<()> {
    let mut opts = eframe::NativeOptions::default();
    opts.viewport.inner_size = Some(egui::Vec2{ x: 1080.0, y: 720.0 });
    eframe::run_native("SARX SecureCam", opts, Box::new(|_cc| Box::<App>::default()))
}
