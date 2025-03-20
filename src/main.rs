#![allow(non_snake_case)]
use clap::Parser;
use std::arch::x86_64::*;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Parser)]
struct Options {
    path: std::path::PathBuf,
}

struct Digest([[u8; 4]; 8]);

impl AsRef<[[u8; 4]; 8]> for Digest {
    fn as_ref(&self) -> &[[u8; 4]; 8] {
        &self.0
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for item in self.as_ref().concat().iter().map(|b| format!("{b:02x}")) {
            write!(f, "{item}")?
        }
        Ok(())
    }
}

#[inline]
unsafe fn process_chunk(
    chunk: &[u8; 64],
    h0: &mut u32,
    h1: &mut u32,
    h2: &mut u32,
    h3: &mut u32,
    h4: &mut u32,
    h5: &mut u32,
    h6: &mut u32,
    h7: &mut u32,
) {
    let mut schedule = [
        _mm_shuffle_epi8(
            _mm_loadu_si128((chunk as *const u8).add(0) as *const __m128i),
            _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3),
        ),
        _mm_shuffle_epi8(
            _mm_loadu_si128((chunk as *const u8).add(16) as *const __m128i),
            _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3),
        ),
        _mm_shuffle_epi8(
            _mm_loadu_si128((chunk as *const u8).add(32) as *const __m128i),
            _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3),
        ),
        _mm_shuffle_epi8(
            _mm_loadu_si128((chunk as *const u8).add(48) as *const __m128i),
            _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3),
        ),
        _mm_setzero_si128(),
        _mm_setzero_si128(),
        _mm_setzero_si128(),
        _mm_setzero_si128(),
        _mm_setzero_si128(),
        _mm_setzero_si128(),
        _mm_setzero_si128(),
        _mm_setzero_si128(),
        _mm_setzero_si128(),
        _mm_setzero_si128(),
        _mm_setzero_si128(),
        _mm_setzero_si128(),
    ];

    // For t = 16 to 63
    //     Wt = SSIG1(W(t-2)) + W(t-7) + SSIG0(w(t-15)) + W(t-16)
    for extend_round in 4..16 {
        let mut tmp = _mm_sha256msg1_epu32(schedule[extend_round - 4], schedule[extend_round - 3]);
        let w7 = _mm_alignr_epi8(schedule[extend_round - 1], schedule[extend_round - 2], 4);
        tmp = _mm_add_epi32(tmp, w7);
        schedule[extend_round] = _mm_sha256msg2_epu32(tmp, schedule[extend_round - 1])
    }

    // Perform 2 rounds of SHA256 operation using an initial SHA256 state (C,D,G,H) from a, an initial SHA256 state (A,B,E,F)
    let mut state0 = _mm_set_epi32(*h0 as i32, *h1 as i32, *h4 as i32, *h5 as i32);
    let mut state1 = _mm_set_epi32(*h2 as i32, *h3 as i32, *h6 as i32, *h7 as i32);

    let state0_save = state0;
    let state1_save = state1;

    for sha_round in 0..16 {
        let round_idx = sha_round * 4;
        let k_const = _mm_set_epi32(
            K[round_idx + 3] as i32,
            K[round_idx + 2] as i32,
            K[round_idx + 1] as i32,
            K[round_idx] as i32,
        );

        let w_rounds = schedule[sha_round];
        state1 = _mm_sha256rnds2_epu32(state1, state0, _mm_add_epi32(w_rounds, k_const));
        state0 = _mm_sha256rnds2_epu32(
            state0,
            state1,
            _mm_add_epi32(_mm_srli_si128(w_rounds, 8), _mm_srli_si128(k_const, 8)),
        );
    }

    state0 = _mm_add_epi32(state0, state0_save);
    state1 = _mm_add_epi32(state1, state1_save);

    *h0 = _mm_extract_epi32(state0, 3) as u32;
    *h1 = _mm_extract_epi32(state0, 2) as u32;
    *h2 = _mm_extract_epi32(state1, 3) as u32;
    *h3 = _mm_extract_epi32(state1, 2) as u32;
    *h4 = _mm_extract_epi32(state0, 1) as u32;
    *h5 = _mm_extract_epi32(state0, 0) as u32;
    *h6 = _mm_extract_epi32(state1, 1) as u32;
    *h7 = _mm_extract_epi32(state1, 0) as u32;
}

fn compute_sha256<T>(mut reader: T) -> Digest
where
    T: std::io::Read,
{
    let mut h0: u32 = 0x6a09e667;
    let mut h1: u32 = 0xbb67ae85;
    let mut h2: u32 = 0x3c6ef372;
    let mut h3: u32 = 0xa54ff53a;
    let mut h4: u32 = 0x510e527f;
    let mut h5: u32 = 0x9b05688c;
    let mut h6: u32 = 0x1f83d9ab;
    let mut h7: u32 = 0x5be0cd19;

    let mut chunk = [0u8; 64];

    // the spec asks for u64 no matter what usize happened to be on that machine
    let mut len_bits: u64 = 0;

    unsafe {
        while let Ok(bytes_read) = reader.read(&mut chunk) {
            len_bits += bytes_read as u64 * 8;
            match bytes_read {
                64 => process_chunk(
                    &chunk, &mut h0, &mut h1, &mut h2, &mut h3, &mut h4, &mut h5, &mut h6, &mut h7,
                ),
                0..56 => {
                    chunk[bytes_read] = 0b10000000;
                    chunk[bytes_read + 1..56].fill(0);
                    chunk[56..].copy_from_slice(&len_bits.to_be_bytes());
                    process_chunk(
                        &chunk, &mut h0, &mut h1, &mut h2, &mut h3, &mut h4, &mut h5, &mut h6,
                        &mut h7,
                    );
                    break;
                }
                56..64 => {
                    chunk[bytes_read] = 0b10000000;
                    chunk[bytes_read + 1..].fill(0);
                    process_chunk(
                        &chunk, &mut h0, &mut h1, &mut h2, &mut h3, &mut h4, &mut h5, &mut h6,
                        &mut h7,
                    );
                    chunk.fill(0);
                    chunk[56..].copy_from_slice(&len_bits.to_be_bytes());
                    process_chunk(
                        &chunk, &mut h0, &mut h1, &mut h2, &mut h3, &mut h4, &mut h5, &mut h6,
                        &mut h7,
                    );
                    break;
                }
                _ => unreachable!(),
            }
        }
    }

    Digest([
        h0.to_be_bytes(),
        h1.to_be_bytes(),
        h2.to_be_bytes(),
        h3.to_be_bytes(),
        h4.to_be_bytes(),
        h5.to_be_bytes(),
        h6.to_be_bytes(),
        h7.to_be_bytes(),
    ])
}

fn main() -> anyhow::Result<()> {
    let options = Options::parse();
    let mut reader =
        std::io::BufReader::with_capacity(4096 * 256, std::fs::File::open(&options.path)?);

    println!(
        "{hash}  {fname}",
        hash = compute_sha256(&mut reader).to_string(),
        fname = options
            .path
            .to_str()
            .ok_or(anyhow::anyhow!("The file path is not a valid UTF8 string"))?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        assert_eq!(
            compute_sha256(std::io::Cursor::new("")).to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()
        )
    }

    #[test]
    fn brown_fox() {
        assert_eq!(
            compute_sha256(std::io::Cursor::new(
                "The quick brown fox jumps over the lazy dog"
            ))
            .to_string(),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592".to_string()
        )
    }
}
