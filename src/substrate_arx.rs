// src/substrate_arx.rs
//
// Substrate ARX-256 keystream core (stateless CTR mode).
// - 256-bit key: (k0,k1,k2,k3)
// - 64-bit counter per block
// - Block size: 32 bytes (4×u64)
// - We map (postmix, offset) → (k0..k3, ctr0) via BLAKE3 in sarx.rs.

#![allow(dead_code)]

const ROUNDS: usize = 8; // same as substrate_stream prototype

// Manually unrolled; same mixing, better ILP for LLVM.
#[inline(always)]
fn arx_rounds(mut x0: u64, mut x1: u64, mut x2: u64, mut x3: u64) -> (u64, u64, u64, u64) {
    // 1
    x0 = x0.wrapping_add(x1); x3 ^= x0; x3 = x3.rotate_left(27);
    x2 = x2.wrapping_add(x3); x1 ^= x2; x1 = x1.rotate_left(31);
    x0 = x0.wrapping_add(x2); x3 ^= x0; x3 = x3.rotate_left(17);
    x1 = x1.wrapping_add(x3); x2 ^= x1; x2 = x2.rotate_left(23);
    // 2
    x0 = x0.wrapping_add(x1); x3 ^= x0; x3 = x3.rotate_left(27);
    x2 = x2.wrapping_add(x3); x1 ^= x2; x1 = x1.rotate_left(31);
    x0 = x0.wrapping_add(x2); x3 ^= x0; x3 = x3.rotate_left(17);
    x1 = x1.wrapping_add(x3); x2 ^= x1; x2 = x2.rotate_left(23);
    // 3
    x0 = x0.wrapping_add(x1); x3 ^= x0; x3 = x3.rotate_left(27);
    x2 = x2.wrapping_add(x3); x1 ^= x2; x1 = x1.rotate_left(31);
    x0 = x0.wrapping_add(x2); x3 ^= x0; x3 = x3.rotate_left(17);
    x1 = x1.wrapping_add(x3); x2 ^= x1; x2 = x2.rotate_left(23);
    // 4
    x0 = x0.wrapping_add(x1); x3 ^= x0; x3 = x3.rotate_left(27);
    x2 = x2.wrapping_add(x3); x1 ^= x2; x1 = x1.rotate_left(31);
    x0 = x0.wrapping_add(x2); x3 ^= x0; x3 = x3.rotate_left(17);
    x1 = x1.wrapping_add(x3); x2 ^= x1; x2 = x2.rotate_left(23);
    // 5
    x0 = x0.wrapping_add(x1); x3 ^= x0; x3 = x3.rotate_left(27);
    x2 = x2.wrapping_add(x3); x1 ^= x2; x1 = x1.rotate_left(31);
    x0 = x0.wrapping_add(x2); x3 ^= x0; x3 = x3.rotate_left(17);
    x1 = x1.wrapping_add(x3); x2 ^= x1; x2 = x2.rotate_left(23);
    // 6
    x0 = x0.wrapping_add(x1); x3 ^= x0; x3 = x3.rotate_left(27);
    x2 = x2.wrapping_add(x3); x1 ^= x2; x1 = x1.rotate_left(31);
    x0 = x0.wrapping_add(x2); x3 ^= x0; x3 = x3.rotate_left(17);
    x1 = x1.wrapping_add(x3); x2 ^= x1; x2 = x2.rotate_left(23);
    // 7
    x0 = x0.wrapping_add(x1); x3 ^= x0; x3 = x3.rotate_left(27);
    x2 = x2.wrapping_add(x3); x1 ^= x2; x1 = x1.rotate_left(31);
    x0 = x0.wrapping_add(x2); x3 ^= x0; x3 = x3.rotate_left(17);
    x1 = x1.wrapping_add(x3); x2 ^= x1; x2 = x2.rotate_left(23);
    // 8
    x0 = x0.wrapping_add(x1); x3 ^= x0; x3 = x3.rotate_left(27);
    x2 = x2.wrapping_add(x3); x1 ^= x2; x1 = x1.rotate_left(31);
    x0 = x0.wrapping_add(x2); x3 ^= x0; x3 = x3.rotate_left(17);
    x1 = x1.wrapping_add(x3); x2 ^= x1; x2 = x2.rotate_left(23);
    (x0, x1, x2, x3)
}

pub fn arx256_fill(state: (u64, u64, u64, u64), ctr0: u64, offset: u64, out: &mut [u8]) {
    let n = out.len();
    if n == 0 { return; }
    const BLOCK: usize = 32;
    let (k0, k1, k2, k3) = state;

    // Find starting block and byte skip
    let mut block  = (offset / BLOCK as u64) as u64;
    let mut skip   = (offset as usize) & (BLOCK - 1);
    let mut written = 0usize;

    // Hoist the 64-bit multiply: mul = block*C; update with mul += C each block
    const C: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut mul = block.wrapping_mul(C);

    // Write a block directly into dst, allowing an initial skip
    #[inline(always)]
    fn write_block(dst: &mut [u8], x0: u64, x1: u64, x2: u64, x3: u64, skip: usize) -> usize {
        let mut buf = [0u8; BLOCK];
        buf[0..8].copy_from_slice(&x0.to_le_bytes());
        buf[8..16].copy_from_slice(&x1.to_le_bytes());
        buf[16..24].copy_from_slice(&x2.to_le_bytes());
        buf[24..32].copy_from_slice(&x3.to_le_bytes());
        let take = dst.len().min(BLOCK - skip);
        dst[..take].copy_from_slice(&buf[skip..skip + take]);
        take
    }

    // Head (if we start mid-block)
    if skip != 0 && written < n {
        let mut x0 = k0 ^ mul;
        let mut x1 = k1;
        let mut x2 = k2;
        let mut x3 = k3 ^ block;
        let (y0,y1,y2,y3) = arx_rounds(x0,x1,x2,x3);
        x0 = y0.wrapping_add(x0);
        x1 = y1.wrapping_add(x1);
        x2 = y2.wrapping_add(x2);
        x3 = y3.wrapping_add(x3);

        written += write_block(&mut out[written..], x0,x1,x2,x3, skip);
        block = block.wrapping_add(1);
        mul   = mul.wrapping_add(C);
        skip = 0;
    }

    // Full blocks
    while written + BLOCK <= n {
        let mut x0 = k0 ^ mul;
        let mut x1 = k1;
        let mut x2 = k2;
        let mut x3 = k3 ^ block;
        let (y0,y1,y2,y3) = arx_rounds(x0,x1,x2,x3);
        x0 = y0.wrapping_add(x0);
        x1 = y1.wrapping_add(x1);
        x2 = y2.wrapping_add(x2);
        x3 = y3.wrapping_add(x3);

        let dst = &mut out[written..written + BLOCK];
        dst[0..8].copy_from_slice(&x0.to_le_bytes());
        dst[8..16].copy_from_slice(&x1.to_le_bytes());
        dst[16..24].copy_from_slice(&x2.to_le_bytes());
        dst[24..32].copy_from_slice(&x3.to_le_bytes());

        written += BLOCK;
        block = block.wrapping_add(1);
        mul   = mul.wrapping_add(C);
    }

    // Tail
    if written < n {
        let mut x0 = k0 ^ mul;
        let mut x1 = k1;
        let mut x2 = k2;
        let mut x3 = k3 ^ block;
        let (y0,y1,y2,y3) = arx_rounds(x0,x1,x2,x3);
        x0 = y0.wrapping_add(x0);
        x1 = y1.wrapping_add(x1);
        x2 = y2.wrapping_add(x2);
        x3 = y3.wrapping_add(x3);

        let _ = write_block(&mut out[written..], x0,x1,x2,x3, 0);
    }
}

/// One 256-bit block: keyed by (k0..k3), indexed by counter `ctr`.
#[inline]
fn arx_block(state: (u64, u64, u64, u64), ctr: u64) -> (u64, u64, u64, u64) {
    let (k0, k1, k2, k3) = state;

    // simple ctr injection (same structure as your substrate_stream)
    let mut x0 = k0 ^ ctr.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut x1 = k1;
    let mut x2 = k2;
    let mut x3 = k3 ^ ctr;

    let o0 = x0;
    let o1 = x1;
    let o2 = x2;
    let o3 = x3;

    let (y0, y1, y2, y3) = arx_rounds(x0, x1, x2, x3);

    x0 = y0.wrapping_add(o0);
    x1 = y1.wrapping_add(o1);
    x2 = y2.wrapping_add(o2);
    x3 = y3.wrapping_add(o3);

    (x0, x1, x2, x3)
}

/// Fill `out` with keystream bytes produced from:
///   - 256-bit key/state `state`
///   - base counter `ctr0`
///   - *byte* offset `offset` within the infinite stream.
///
/// We treat the stream as 32-byte blocks:
///   block i = ARX(state, ctr0 + i)
/// and slice appropriately using offset and out.len().
pub fn arx256_fill(state: (u64, u64, u64, u64), ctr0: u64, offset: u64, out: &mut [u8]) {
    let n = out.len();
    if n == 0 {
        return;
    }

    const BLOCK_BYTES: usize = 32;

    // which block to start from, and where inside that block
    let start_block = (offset / BLOCK_BYTES as u64) as u64;
    let mut skip = (offset % BLOCK_BYTES as u64) as usize;

    let mut produced = 0usize;
    let mut ctr = ctr0 + start_block;
    let mut block_buf = [0u8; BLOCK_BYTES];

    while produced < n {
        let (x0, x1, x2, x3) = arx_block(state, ctr);
        ctr = ctr.wrapping_add(1);

        block_buf[0..8].copy_from_slice(&x0.to_le_bytes());
        block_buf[8..16].copy_from_slice(&x1.to_le_bytes());
        block_buf[16..24].copy_from_slice(&x2.to_le_bytes());
        block_buf[24..32].copy_from_slice(&x3.to_le_bytes());

        let available = BLOCK_BYTES - skip;
        let needed = n - produced;
        let take = if available < needed { available } else { needed };

        out[produced..produced + take].copy_from_slice(&block_buf[skip..skip + take]);
        produced += take;
        skip = 0;
    }
}
