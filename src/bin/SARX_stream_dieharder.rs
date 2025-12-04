//! §8.1.0 Overview — SARX v1 ARX Stream (dieharder/practrand)
//! - persistent worker pool
//! - per-round contiguous stripes
//! - single stdout write per chunk
//!
//! Usage:
//!   cargo run --release --bin sarx_stream_dieharder | dieharder -a -g 200
//!   SARX_THREADS=6 SARX_CHUNK_MB=64 cargo run --release --bin sarx_stream_dieharder | \
//!       /home/luke-miller/Desktop/PractRand/RNG_test stdin32 -tlmax 40
//!
//! /* =============================================================================
//!  * SARX — sarx_stream_dieharder.rs — Program v8.1.0
//!  * Numbering: Program=8.1.0, Sections=§8.X.0, Subsections=§8.X.Y
//!  * =============================================================================
//!  */

// ============================================================================
// §8.2.0 Imports & Crate Uses
// ============================================================================
use anyhow::Result;
use blake3::Hasher as Blake3;
use zeroize::Zeroize;
use rand::RngCore;
use std::env;
use std::io::{self, Write};
use std::sync::{Arc, Mutex, Condvar};
use std::thread;

use sarx::sarx::{generate_config_with_timestamp, generate_stream, SARXConfig};

// ============================================================================
// §8.3.0 Tiny Helpers (byte utils, padding)
// ============================================================================
#[inline] fn u64_be(x: u64) -> [u8; 8] { x.to_be_bytes() }
#[inline] fn round_up_32(x: usize) -> usize { (x + 31) & !31 }

// ============================================================================
// §8.4.0 Password Generation (Unicode 30..101 cps)
// ============================================================================
fn random_unicode_password() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let target = 30 + (rng.gen::<u32>() as usize % 72); // 30..101
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
// §8.8.0 Worker Pool & Job Structures
// Purpose: simple per-round job dispatch (1:1 with C design).
// ============================================================================
#[derive(Copy, Clone)]
struct Job {
    offset: u64,
    len: usize,
    out_ptr: *mut u8,
}

unsafe impl Send for Job {}
unsafe impl Sync for Job {}

struct Shared {
    jobs: Vec<Job>,
    round_id: u64,
    finished: usize,
    stop: bool,
}

struct Pool {
    threads: usize,
    shared: Arc<(Mutex<Shared>, Condvar, Condvar)>,
    handles: Vec<thread::JoinHandle<()>>,
    _cfg: Arc<SARXConfig>,
}

impl Pool {
    // §8.8.1 Pool::new — spawn workers and set up shared state
    fn new(threads_hint: usize, cfg: Arc<SARXConfig>) -> Self {
        // clamp to (HW-2) minimum 1 (matches C)
        let hw = num_cpus::get().max(1);
        let max_allowed = if hw >= 3 { hw - 2 } else { 1 };
        let threads = threads_hint.clamp(1, max_allowed);

        let shared = Arc::new((
            Mutex::new(Shared {
                jobs: vec![Job { offset: 0, len: 0, out_ptr: std::ptr::null_mut() }; threads],
                round_id: 0,
                finished: 0,
                stop: false,
            }),
            Condvar::new(), // start_cv
            Condvar::new(), // done_cv
        ));

        let mut handles = Vec::with_capacity(threads);
        for lane in 0..threads {
            let shared_cl = Arc::clone(&shared);
            let cfg_cl = Arc::clone(&cfg);
            let handle = thread::spawn(move || {
                let (mtx, start_cv, done_cv) = &*shared_cl;
                let mut local_round = 0u64;
                loop {
                    // wait for new round or stop
                    let mut st = mtx.lock().unwrap();
                    while !st.stop && st.round_id == local_round {
                        st = start_cv.wait(st).unwrap();
                    }
                    if st.stop { break; }
                    local_round = st.round_id;

                    // snapshot my job
                    let job = st.jobs[lane];
                    drop(st);

                    // do work
                    if job.len > 0 && !job.out_ptr.is_null() {
                        // Safety: coordinator gives non-overlapping slices into a valid buffer
                        let out_slice = unsafe { std::slice::from_raw_parts_mut(job.out_ptr, job.len) };
                        // generate_stream writes exactly job.len bytes into out_slice
                        if let Err(_e) = generate_stream(&cfg_cl, None, job.offset, job.len, out_slice) {
                            // If a worker fails, we still mark finished; coordinator can decide to stop.
                        }
                    }

                    // mark finished
                    let mut st = mtx.lock().unwrap();
                    st.finished += 1;
                    if st.finished == st.jobs.len() {
                        done_cv.notify_one();
                    }
                    // loop for next round
                }
            });
            handles.push(handle);
        }

        Self { threads, shared, handles, _cfg: cfg }
    }

    // §8.8.2 Pool::run_round — assign striped jobs and block until done
    fn run_round(&self, start_offset: u64, total_len: usize, out_buf: &mut [u8]) {
        let lanes = self.threads;
        let base = total_len / lanes;
        let rem = total_len % lanes;

        // prepare jobs
        let (mtx, start_cv, done_cv) = &*self.shared;
        {
            let mut st = mtx.lock().unwrap();
            let mut off = start_offset;
            let mut pos = 0usize;
            for i in 0..lanes {
                let len_i = base + if i < rem { 1 } else { 0 };
                let out_ptr = if len_i > 0 { unsafe { out_buf.as_mut_ptr().add(pos) } } else { std::ptr::null_mut() };
                st.jobs[i] = Job { offset: off, len: len_i, out_ptr };
                off += len_i as u64;
                pos += len_i;
            }
            st.finished = 0;
            st.round_id = st.round_id.wrapping_add(1);
            start_cv.notify_all();
        }

        // wait for all workers to finish this round
        let mut st = mtx.lock().unwrap();
        while st.finished < lanes {
            st = done_cv.wait(st).unwrap();
        }
    }
}

impl Drop for Pool {
    // §8.8.3 Pool::drop — signal stop & join workers
    fn drop(&mut self) {
        // signal stop & join
        let (mtx, start_cv, _done_cv) = &*self.shared;
        {
            let mut st = mtx.lock().unwrap();
            st.stop = true;
            start_cv.notify_all();
        }
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

// ============================================================================
// §8.6.0 Main — Seed, Config, Stream Loop
// ============================================================================
fn main() -> Result<()> {
    // §8.6.1 Unbuffered stdout (pipe-friendly)
    let mut stdout = io::stdout().lock();

    // §8.6.2 Password / seed material (supports: sarx_stream_dieharder pw <password>)
    let argv: Vec<String> = env::args().collect();
    let password = if argv.len() == 3 && argv[1] == "pw" {
        let cp = argv[2].chars().count();
        if cp < 30 || cp > 100 {
            anyhow::bail!("Password must be 30–100 Unicode codepoints (found {}).", cp);
        }
        argv[2].clone()
    } else {
        random_unicode_password()
    };

    // §8.6.3 Timestamp + nonce
    let timestamp_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?.as_nanos() as u64;
    let mut nonce12 = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce12);

    // §8.6.4 Salt = BLAKE3(ts || nonce)  (for Argon2 parity; not used by ARX stream)
    let mut salt_in = [0u8; 20];
    salt_in[..8].copy_from_slice(&u64_be(timestamp_ns));
    salt_in[8..].copy_from_slice(&nonce12);
    let mut hh = Blake3::new(); hh.update(&salt_in);
    let mut salt32 = [0u8; 32]; hh.finalize_xof().fill(&mut salt32);

    // §8.6.5 Argon2id OKM (currently unused by keystream; kept for full-pipeline parity)
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

    // §8.6.6 Config from raw password (timestamp bound) — this seeds ARX-256 once and for all
    let cfg = Arc::new(generate_config_with_timestamp(&password, None, 0, timestamp_ns)?);

    // §8.6.8 Threads & chunk sizing
    let hw = num_cpus::get().max(1);
    let mut threads_hint = hw;
    if let Ok(s) = env::var("SARX_THREADS") {
        if let Ok(t) = s.parse::<usize>() { if t >= 1 { threads_hint = t; } }
    }
    let chunk_mb = env::var("SARX_CHUNK_MB").ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1);
    let chunk = chunk_mb.max(1) * 1024 * 1024;

    {
        // §8.6.9 Pool + streaming loop: parallel fill → single write
        let pool = Pool::new(threads_hint, Arc::clone(&cfg));

        let mut buf = vec![0u8; chunk];
        let mut offset: u64 = 0;

        loop {
            pool.run_round(offset, chunk, &mut buf);

            if let Err(_e) = stdout.write_all(&buf) {
                // sink closed (dieharder/PractRand ended) → exit cleanly
                break;
            }
            offset = offset.wrapping_add(chunk as u64);
        }

        // hygiene
        buf.zeroize();
    } // pool dropped; Arcs released

    // §8.6.10 Zeroization & tidy
    okm.zeroize();
    salt32.zeroize();
    nonce12.zeroize();
    Ok(())
}
