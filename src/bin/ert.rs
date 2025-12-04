// src/bin/ert.rs
//
// Entropy Resonance Test (ERT) harness for Substrate ARX-256.
// - Generates N keystreams of M bytes each from the ARX core.
// - Builds a bit matrix: rows = keystreams, cols = bit index.
// - For each diagonal offset d, computes H2 entropy of the diagonal:
//     diag_d = { M[row][row + d] where in-bounds }.
// - Prints CSV: offset,len,entropy
//
// Usage examples:
//   cargo run --release --bin ert
//   cargo run --release --bin ert -- 32 4096    # 32 streams, 4096 bytes each
//   cargo run --release --bin ert -- 64 16384   # 64 streams, 16KiB each
//
// You can then plot offset vs entropy in Python, gnuplot, etc.

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use std::env;

// -------- ARX core (same as your stream.rs) --------

const ROUNDS: usize = 8;

#[inline]
fn arx_rounds(mut x0: u64, mut x1: u64, mut x2: u64, mut x3: u64) -> (u64, u64, u64, u64) {
    for _ in 0..ROUNDS {
        // "column" step
        x0 = x0.wrapping_add(x1);
        x3 ^= x0;
        x3 = x3.rotate_left(27);

        x2 = x2.wrapping_add(x3);
        x1 ^= x2;
        x1 = x1.rotate_left(31);

        // "diagonal-ish" cross step
        x0 = x0.wrapping_add(x2);
        x3 ^= x0;
        x3 = x3.rotate_left(17);

        x1 = x1.wrapping_add(x3);
        x2 ^= x1;
        x2 = x2.rotate_left(23);
    }
    (x0, x1, x2, x3)
}

/// One 256-bit block given state and counter.
/// state: (k0,k1,k2,k3) is the 256-bit key/state.
/// ctr: 64-bit block counter.
fn arx_block(state: (u64, u64, u64, u64), ctr: u64) -> (u64, u64, u64, u64) {
    let (k0, k1, k2, k3) = state;

    // Mix counter into two words
    let mut x0 = k0 ^ ctr.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut x1 = k1;
    let mut x2 = k2;
    let mut x3 = k3 ^ ctr;

    let o0 = x0;
    let o1 = x1;
    let o2 = x2;
    let o3 = x3;

    let (y0, y1, y2, y3) = arx_rounds(x0, x1, x2, x3);

    // feedforward
    x0 = y0.wrapping_add(o0);
    x1 = y1.wrapping_add(o1);
    x2 = y2.wrapping_add(o2);
    x3 = y3.wrapping_add(o3);

    (x0, x1, x2, x3)
}

// -------- Keystream generation into a matrix --------

fn generate_keystreams(num_streams: usize, bytes_per_stream: usize) -> Vec<Vec<u8>> {
    let mut rng = StdRng::from_entropy();
    let mut streams = Vec::with_capacity(num_streams);

    for _ in 0..num_streams {
        // Independent random key/state per stream
        let k0 = rng.next_u64();
        let k1 = rng.next_u64();
        let k2 = rng.next_u64();
        let k3 = rng.next_u64();
        let mut ctr = rng.next_u64();
        let mut state = (k0, k1, k2, k3);

        let mut out = Vec::with_capacity(bytes_per_stream);
        while out.len() < bytes_per_stream {
            let (x0, x1, x2, x3) = arx_block(state, ctr);
            // evolve state (same as stream.rs)
            state = (x0, x1, x2, x3);
            ctr = ctr.wrapping_add(1);

            for word in [x0, x1, x2, x3] {
                let bytes = word.to_le_bytes();
                let remaining = bytes_per_stream - out.len();
                let take = remaining.min(8);
                out.extend_from_slice(&bytes[..take]);
                if out.len() >= bytes_per_stream {
                    break;
                }
            }
        }
        streams.push(out);
    }

    streams
}

fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    // Bit order doesn't matter for entropy; choose MSB-first for readability.
    for b in bytes {
        for i in (0..8).rev() {
            bits.push((b >> i) & 1);
        }
    }
    bits
}

// -------- ERT: diagonal entropy computation --------

fn compute_diagonal_entropies(bit_matrix: &[Vec<u8>]) -> Vec<(isize, usize, f64)> {
    let rows = bit_matrix.len();
    if rows == 0 {
        return Vec::new();
    }
    let cols = bit_matrix[0].len();
    let rows_i = rows as isize;
    let cols_i = cols as isize;

    // Require diagonals to hit all streams (or at least most).
    // For a 64×N matrix, max len is 64, so this effectively enforces len == rows.
    let min_diag_len = rows; // this is the key change

    let mut results = Vec::new();

    for d in -(cols_i - 1)..=(cols_i - 1) {
        let mut ones = 0usize;
        let mut len = 0usize;
        for row in 0..rows {
            let col_i = row as isize + d;
            if col_i >= 0 && col_i < cols_i {
                let col = col_i as usize;
                let bit = bit_matrix[row][col];
                ones += bit as usize;
                len += 1;
            }
        }

        if len < min_diag_len {
            continue;
        }

        let p1 = ones as f64 / len as f64;
        let p0 = 1.0 - p1;
        let mut h = 0.0;
        if p1 > 0.0 {
            h -= p1 * p1.log2();
        }
        if p0 > 0.0 {
            h -= p0 * p0.log2();
        }
        results.push((d, len, h));
    }

    results
}

fn main() {
    // Defaults: modest but non-toy; tweak as needed.
    // e.g. 32 streams × 4096 bytes, or 64 × 16384 for more data.
    let args: Vec<String> = env::args().collect();
    let (num_streams, bytes_per_stream) = if args.len() >= 3 {
        let n = args[1].parse::<usize>().unwrap_or(32);
        let m = args[2].parse::<usize>().unwrap_or(4096);
        (n, m)
    } else {
        (32, 4096)
    };

    eprintln!(
        "Generating {} streams × {} bytes each ({} bits per stream)...",
        num_streams,
        bytes_per_stream,
        bytes_per_stream * 8
    );

    let streams = generate_keystreams(num_streams, bytes_per_stream);
    let bit_matrix: Vec<Vec<u8>> = streams.iter().map(|s| bytes_to_bits(s)).collect();

    let entropies = compute_diagonal_entropies(&bit_matrix);

    // Summary stats
    let mut min_h = f64::INFINITY;
    let mut max_h = f64::NEG_INFINITY;
    let mut sum_h = 0.0;
    let mut count = 0usize;
    for &(_, _, h) in &entropies {
        if h < min_h {
            min_h = h;
        }
        if h > max_h {
            max_h = h;
        }
        sum_h += h;
        count += 1;
    }
    let mean_h = if count > 0 { sum_h / count as f64 } else { 0.0 };

    eprintln!(
        "Diagonal entropy: min = {:.6}, max = {:.6}, mean = {:.6}, samples = {}",
        min_h, max_h, mean_h, count
    );

    // CSV output: offset,len,entropy
    // You can redirect this to a file: `cargo run --release --bin ert -- 64 16384 > ert_arx256.csv`
    println!("offset,len,entropy");
    for (d, len, h) in entropies {
        println!("{},{},{}", d, len, h);
    }
}