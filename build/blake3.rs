// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// A dependency-free BLAKE3 (night-dragon-maintenance-0, the build
// lane's std-only law, upgraded from the sha256 tree pins): the
// registry-prebuilt lane verifies the staged objects' bytes against
// the ebpf-prebuilt/manifest.toml object pins before embedding them,
// and the pins are blake3 — so the build script needs a blake3.
// Adding a hashing crate as a build-dependency would break the
// manifest's own rule (build.rs stays std-only; the Cargo.toml
// comment block records it), so the algorithm lives here: the
// official BLAKE3 reference design (the hash mode only — no keyed
// hashing, no derive-key, no extendable output beyond the first
// 32 bytes), the compression function, the message permutation, and
// the chunk/parent tree verbatim, no unsafe, one fixed-size stack.
//
// Why blake3 over the sha256 it replaces: the estate's checksum lane
// standardizes on it (the owner's night-dragon-maintenance-0 law, the
// sibling zejtron night-weekly-maintenance-1 shape) — same 256-bit
// digest, a single widely vetted design, and one algorithm across the
// manifest's object pins and the tree pin, matching the b3sum
// sidecars the GitHub Release archives carry.
//
// The suite below is the only thing that executes these vectors —
// `cargo test` never runs build-script tests; the standing runner is:
//   rustc --edition 2021 --test build.rs -o /tmp/zelynic-build-test
//     && /tmp/zelynic-build-test
// The vectors were hashed with the reference b3sum 1.8.7 binary as
// the ground truth (crates.io b3sum, --locked), on deterministic
// inputs ('a' repeated) so the suite can rebuild every input byte
// exactly: the set walks every structural boundary the tree has —
// block edges (63/64/127/128), the chunk edge (1023/1024/1025),
// two- and four-chunk merges (2047/2048/2049/4096/4097), and deep
// parent stacks (8192/16384/16385/100000).

/// One BLAKE3 digest over `data`, as 32 raw bytes (the default hash
/// mode, the zero key, no context string).
pub(crate) fn blake3(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// Lowercase hex rendering of one digest — the manifest pins are hex
/// strings, so the comparison renders both sides the same way.
pub(crate) fn blake3_hex(data: &[u8]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in blake3(data) {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

// ── The spec constants ────────────────────────────────────────────────

const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;

// The BLAKE3 initial chaining value is SHA-256's (FIPS 180-4 section
// 5.3.3, the first eight primes' square-root fractional parts).
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

// The message word permutation BLAKE3 applies between rounds.
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

// The chunk-tree depth bound: 2^54 chunks is beyond any object this
// lane will ever see, and the stack size is the reference constant.
const MAX_DEPTH: usize = 54;

// ── The compression function ──────────────────────────────────────────

fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    // Mix the columns.
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    // Mix the diagonals.
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

fn permute(m: &mut [u32; 16]) {
    let mut permuted = [0u32; 16];
    for (slot, source) in permuted.iter_mut().zip(MSG_PERMUTATION.iter()) {
        *slot = m[*source];
    }
    *m = permuted;
}

fn compress(
    chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut block = *block_words;
    // Seven rounds, permuting the message words between them.
    for round_index in 0..7 {
        if round_index > 0 {
            permute(&mut block);
        }
        round(&mut state, &block);
    }
    // The upper half feeds the next compression's chaining value; the
    // lower half is the output, XOR-mixed with the input value.
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i];
    }
    state
}

fn words_from_le_bytes_64(bytes: &[u8; BLOCK_LEN]) -> [u32; 16] {
    let mut words = [0u32; 16];
    for (slot, word) in words.iter_mut().enumerate() {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(&bytes[4 * slot..4 * slot + 4]);
        *word = u32::from_le_bytes(raw);
    }
    words
}

// ── Chunk state and outputs ───────────────────────────────────────────

struct Output {
    input_chaining_value: [u32; 8],
    block_words: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        let full = compress(
            &self.input_chaining_value,
            &self.block_words,
            self.counter,
            self.block_len,
            self.flags,
        );
        let mut cv = [0u32; 8];
        cv.copy_from_slice(&full[..8]);
        cv
    }
}

struct ChunkState {
    cv: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
    flags: u32,
}

impl ChunkState {
    fn new(key_words: &[u32; 8], chunk_counter: u64, flags: u32) -> Self {
        Self {
            cv: *key_words,
            chunk_counter,
            block: [0u8; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * (self.blocks_compressed as usize) + (self.block_len as usize)
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            // Only a FULL block gets compressed here — a partial tail
            // stays in the buffer for the next update or the finalize.
            if self.block_len as usize == BLOCK_LEN {
                let block_words = words_from_le_bytes_64(&self.block);
                let cv = self.cv;
                self.cv = compress(
                    &cv,
                    &block_words,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.flags | self.start_flag(),
                )[..8]
                    .try_into()
                    .expect("eight words");
                self.blocks_compressed += 1;
                self.block = [0u8; BLOCK_LEN];
                self.block_len = 0;
            }
            let want = BLOCK_LEN - self.block_len as usize;
            let take = want.min(input.len());
            self.block[self.block_len as usize..][..take].copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        Output {
            input_chaining_value: self.cv,
            block_words: words_from_le_bytes_64(&self.block),
            counter: self.chunk_counter,
            block_len: u32::from(self.block_len),
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

fn parent_output(
    left_child_cv: [u32; 8],
    right_child_cv: [u32; 8],
    key_words: &[u32; 8],
    flags: u32,
) -> Output {
    let mut block_words = [0u32; 16];
    block_words[..8].copy_from_slice(&left_child_cv);
    block_words[8..].copy_from_slice(&right_child_cv);
    Output {
        input_chaining_value: *key_words,
        block_words,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: PARENT | flags,
    }
}

// ── The hasher: chunk walk plus the subtree CV stack ──────────────────

struct Hasher {
    chunk_state: ChunkState,
    key_words: [u32; 8],
    cv_stack: [[u32; 8]; MAX_DEPTH],
    cv_stack_len: u8,
    flags: u32,
}

impl Hasher {
    fn new() -> Self {
        Self {
            chunk_state: ChunkState::new(&IV, 0, 0),
            key_words: IV,
            cv_stack: [[0u32; 8]; MAX_DEPTH],
            cv_stack_len: 0,
            flags: 0,
        }
    }

    fn push_stack(&mut self, cv: [u32; 8]) {
        self.cv_stack[self.cv_stack_len as usize] = cv;
        self.cv_stack_len += 1;
    }

    fn pop_stack(&mut self) -> [u32; 8] {
        self.cv_stack_len -= 1;
        self.cv_stack[self.cv_stack_len as usize]
    }

    // The left-to-right tree merge: a completed chunk merges with the
    // stack while its subtree is even-sized (the counter's low bits
    // name the subtree's shape), exactly the reference algorithm.
    fn add_chunk_chaining_value(&mut self, mut new_cv: [u32; 8], total_len: u64) {
        let mut total_len = total_len;
        while total_len & 1 == 0 {
            let left = self.pop_stack();
            let right = new_cv;
            new_cv = parent_output(left, right, &self.key_words, self.flags).chaining_value();
            total_len >>= 1;
        }
        self.push_stack(new_cv);
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk_state.len() == CHUNK_LEN {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_chaining_value(chunk_cv, total_chunks);
                self.chunk_state = ChunkState::new(&self.key_words, total_chunks, self.flags);
            }
            let want = CHUNK_LEN - self.chunk_state.len();
            let take = want.min(input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    fn finalize(&self, out: &mut [u8; 32]) {
        let mut output = self.chunk_state.output();
        let mut parents_remaining = self.cv_stack_len as usize;
        while parents_remaining > 0 {
            parents_remaining -= 1;
            let left = self.cv_stack[parents_remaining];
            let right = output.chaining_value();
            output = parent_output(left, right, &self.key_words, self.flags);
        }
        // The 32-byte digest is the first output block's first eight
        // words, little-endian — the only extendable-output range the
        // manifest's 256-bit pins need.
        let full = compress(
            &output.input_chaining_value,
            &output.block_words,
            output.counter,
            output.block_len,
            output.flags | ROOT,
        );
        let (slots, _) = out.as_chunks_mut::<4>();
        for (slot, word) in slots.iter_mut().zip(full.iter()) {
            slot.copy_from_slice(&word.to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_hex(data: &[u8]) -> String {
        blake3_hex(data)
    }

    fn repeated(count: usize) -> Vec<u8> {
        vec![b'a'; count]
    }

    #[test]
    fn empty_input_matches_the_reference_vector() {
        // b3sum 1.8.7 over an empty stream.
        assert_eq!(
            digest_hex(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn short_input_matches_the_reference_vector() {
        assert_eq!(
            digest_hex(b"abc"),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }

    #[test]
    fn block_boundary_inputs_match_b3sum() {
        // 63/64 (one full block) and 127/128 (two blocks): the block
        // walk and the partial-tail path.
        let cases: [(usize, &str); 4] = [
            (
                63,
                "1a2a060cf56e4a859d80723cac9e2391d3c09a33008483e5424c57fe68629b79",
            ),
            (
                64,
                "472c51290d607f100d2036fdcedd7590bba245e9adeb21364a063b7bb4ca81c7",
            ),
            (
                127,
                "34642f132550dbc2098a799d73431936815317b10786ec69a11c76db3cc5b4b7",
            ),
            (
                128,
                "0753df896d00f20c247f7e8c8977bb84d42f57532a5cc30d8f2ea035c9ce5757",
            ),
        ];
        for (count, expected) in cases {
            assert_eq!(digest_hex(&repeated(count)), expected, "{count} bytes");
        }
    }

    #[test]
    fn chunk_boundary_inputs_match_b3sum() {
        // 1023/1024/1025: the chunk edge — a one-chunk tree, then the
        // first two-chunk merge (the parent-node path).
        let cases: [(usize, &str); 3] = [
            (
                1023,
                "d1a12877ca3fa679de7e9a2af16d67498aaa4ad315f0a98dba2cea3ebc9c0250",
            ),
            (
                1024,
                "5a1c9e5d85d9898297037e8e24f69bb0e604a84c91c3b3ef4784a374812900d9",
            ),
            (
                1025,
                "c59d2e12583df14d951e757a42f1734d355c8c5b1db6b6a33ab2bfabeed40c7d",
            ),
        ];
        for (count, expected) in cases {
            assert_eq!(digest_hex(&repeated(count)), expected, "{count} bytes");
        }
    }

    #[test]
    fn multi_chunk_merges_match_b3sum() {
        // 2047/2048/2049/4096/4097: two- and four-chunk trees, plus
        // the odd tail that keeps the last subtree unmerged.
        let cases: [(usize, &str); 5] = [
            (
                2047,
                "d46a64b4ae2c0a16a9d0f0b3ffc32d12b41433d7c6f55740103051bfc28cbe8e",
            ),
            (
                2048,
                "11654ac17d073b0905429320fee0a34776cb5f10a9767287c70b627fc4f45539",
            ),
            (
                2049,
                "32e4e6d05329fdf8777c2c1f87926ca72210a03abeec282a3b7946783abbd5db",
            ),
            (
                4096,
                "cf657d3fd42311a258afdf3b5261c256983e3deb2bb38980cb0e754db903d549",
            ),
            (
                4097,
                "480623959a661b81089a7b003d4a6206965e06fba7c95f77a984a4dcb774c978",
            ),
        ];
        for (count, expected) in cases {
            assert_eq!(digest_hex(&repeated(count)), expected, "{count} bytes");
        }
    }

    #[test]
    fn deep_parent_stacks_match_b3sum() {
        // 8192/16384/16385/100000: CV-stack depth four and beyond, the
        // stack pop order the finalize walk depends on.
        let cases: [(usize, &str); 4] = [
            (
                8192,
                "4b6d9ef12ab5a1ab11e7441f0460fb4fc7e03e5dfe75a37dec5c43fabbb03b6e",
            ),
            (
                16384,
                "d2613fb519aa95cd328f55dd4551c848920c2209cdcf0debc02500d2ad896407",
            ),
            (
                16385,
                "1403a8de9ee86611aae3766e8c5b08afb16c30e850aa64d24af10a607b686325",
            ),
            (
                100000,
                "4d593f58529cc720a92d1a3c4e0d0f05929bee0bc6e4cc0ede9476ff59c71536",
            ),
        ];
        for (count, expected) in cases {
            assert_eq!(digest_hex(&repeated(count)), expected, "{count} bytes");
        }
    }

    #[test]
    fn one_bit_flip_changes_the_digest() {
        // The avalanche sanity check on the tail-block path.
        let mut input = vec![b'x'; 2049];
        let baseline = digest_hex(&input);
        input[2048] ^= 1;
        assert_ne!(digest_hex(&input), baseline);
    }
}
