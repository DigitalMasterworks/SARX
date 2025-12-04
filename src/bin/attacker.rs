// src/bin/attacker.rs
//! §9.1.0 Overview — Side-Channel Timing Probe (concurrent attacker)
//! Simulates a co-resident “attacker” thread running while SARX encrypts.
//! The attacker never sees the password/keys; it only measures timing jitter
//! from a cache-thrashing probe loop while the victim encrypts a large buffer.
//!
//! /* =============================================================================
//!  * SARX — attacker.rs — Program v9.0.0
//!  * Numbering: Program=9.0.0, Sections=§9.X.0, Subsections=§9.X.Y
//!  * Cross-reference these tags later when building the ToC.
//!  * =============================================================================
//!  */

// ============================================================================
// §9.2.0 Imports & Types
// ============================================================================
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;
use sarx::sarx::{generate_config_with_timestamp, encrypt_sarx, SARXConfig};

// ============================================================================
// §9.3.0 Victim Role
// Purpose: perform SARX encryption on a large buffer while attacker probes.
// ============================================================================
fn victim(cfg: Arc<SARXConfig>, barrier: Arc<Barrier>, data: &[u8], ct: &mut [u8]) {
    barrier.wait(); // §9.3.1 sync start with attacker
    let _ = encrypt_sarx(data, &cfg, None, ct); // §9.3.2 encrypt (mask=None for pure SARX timing)
}

// ============================================================================
// §9.4.0 Attacker Role
// Purpose: run a cache-heavy probe loop, sampling iteration runtimes (ns).
// Notes: The probe touches a 4096-element u64 array to stir caches/PLB.
// ============================================================================
fn attacker(barrier: Arc<Barrier>, duration_ms: u64) {
    barrier.wait(); // §9.4.1 sync start

    let mut timings: Vec<u128> = Vec::new();
    let mut arr = [0u64; 4096]; // §9.4.2 probe buffer to thrash caches

    // §9.4.3 bounded run: cap by iterations and wall-clock duration
    while timings.len() < 100_000 {
        let t0 = Instant::now();

        // §9.4.4 cache-stress pass
        let mut sum = 0u64;
        for i in 0..arr.len() {
            arr[i] = arr[i].wrapping_add(i as u64 ^ sum);
            sum = sum.wrapping_add(arr[i]);
        }

        // §9.4.5 sample elapsed time (ns) for this probe iteration
        let dt = t0.elapsed().as_nanos();
        timings.push(dt);

        if t0.elapsed().as_millis() >= duration_ms as u128 {
            break;
        }
    }

    // §9.4.6 summarize distribution (min/max/mean); export raw if desired
    let min = *timings.iter().min().unwrap_or(&0);
    let max = *timings.iter().max().unwrap_or(&0);
    let avg = timings.iter().sum::<u128>() as f64 / timings.len().max(1) as f64;

    println!(
        "[attacker] iterations={}, min={}ns max={}ns avg={:.2}ns",
        timings.len(),
        min,
        max,
        avg
    );

    // Optional (not implemented here):
    //  - write timings to CSV for two different passwords and compare
    //  - run KS-test / Welch’s t-test to check for distinguishability
}

// ============================================================================
// §9.5.0 Main — Orchestrate Victim & Attacker
// Flow: build config → allocate buffers → barrier sync → join threads.
// ============================================================================
fn main() {
    // §9.5.1 victim password (control). Try different shapes/lengths to test.
    let pw = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // §9.5.2 timestamp bind for SARX config
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    // §9.5.3 build config from password+timestamp (no plaintext binding)
    let cfg = Arc::new(generate_config_with_timestamp(pw, None, 0, ts).unwrap());

    // §9.5.4 victim buffers (32 MiB workload to keep the victim busy)
    let plain = vec![0u8; 32 * 1024 * 1024];
    let ct = vec![0u8; plain.len()];

    // §9.5.5 barrier(2) to align start of victim and attacker
    let barrier = Arc::new(Barrier::new(2));

    let cfg_cl = cfg.clone();
    let barrier_v = barrier.clone();
    let barrier_a = barrier.clone();

    // §9.5.6 spawn victim
    let victim_thread = thread::spawn(move || {
        // (Note: cloning ct for thread closure moves; cost is negligible for this demo)
        victim(cfg_cl, barrier_v, &plain, &mut ct.clone());
    });

    // §9.5.7 spawn attacker (watch ~1 second)
    let attacker_thread = thread::spawn(move || {
        attacker(barrier_a, 1000);
    });

    // §9.5.8 wait for both to complete
    let _ = victim_thread.join();
    let _ = attacker_thread.join();
}

// ============================================================================
// §9.6.0 Experiment Notes (non-functional)
// - Run multiple trials changing only the password (length, Unicode mix, etc.).
// - Save attacker timing vectors to disk; compare distributions across trials.
// - Apply statistical tests (KS-test, MWU, t-test) to detect leakage.
// - Pin threads to cores (taskset) to reduce scheduler noise; disable Turbo.
// - Consider adding background noise threads to emulate multi-tenant systems.
// - If distributions diverge significantly across passwords → investigate.
// ============================================================================
