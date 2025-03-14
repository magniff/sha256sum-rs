#![allow(non_snake_case)]
use clap::Parser;

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
fn process_chunk(
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
    let mut schedule = [0u32; 64];
    for (i, word) in schedule[0..16].iter_mut().enumerate() {
        *word = u32::from_be_bytes([
            chunk[i * 4],
            chunk[i * 4 + 1],
            chunk[i * 4 + 2],
            chunk[i * 4 + 3],
        ]);
    }

    for extend_round in 16..64 {
        let s0 = schedule[extend_round - 15].rotate_right(7)
            ^ schedule[extend_round - 15].rotate_right(18)
            ^ (schedule[extend_round - 15] >> 3);

        let s1 = schedule[extend_round - 2].rotate_right(17)
            ^ schedule[extend_round - 2].rotate_right(19)
            ^ (schedule[extend_round - 2] >> 10);

        schedule[extend_round] = schedule[extend_round - 16]
            .wrapping_add(s0)
            .wrapping_add(schedule[extend_round - 7])
            .wrapping_add(s1);
    }

    let mut a = *h0;
    let mut b = *h1;
    let mut c = *h2;
    let mut d = *h3;
    let mut e = *h4;
    let mut f = *h5;
    let mut g = *h6;
    let mut h = *h7;

    for round in 0..64 {
        let temp1 = h
            .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
            .wrapping_add((e & f) ^ ((!e) & g))
            .wrapping_add(K[round])
            .wrapping_add(unsafe { *schedule.get_unchecked(round) });

        let S0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let temp2 = S0.wrapping_add((a & b) ^ (a & c) ^ (b & c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    *h0 = h0.wrapping_add(a);
    *h1 = h1.wrapping_add(b);
    *h2 = h2.wrapping_add(c);
    *h3 = h3.wrapping_add(d);
    *h4 = h4.wrapping_add(e);
    *h5 = h5.wrapping_add(f);
    *h6 = h6.wrapping_add(g);
    *h7 = h7.wrapping_add(h);
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
                    &chunk, &mut h0, &mut h1, &mut h2, &mut h3, &mut h4, &mut h5, &mut h6, &mut h7,
                );
                break;
            }
            56..64 => {
                chunk[bytes_read] = 0b10000000;
                chunk[bytes_read + 1..].fill(0);
                process_chunk(
                    &chunk, &mut h0, &mut h1, &mut h2, &mut h3, &mut h4, &mut h5, &mut h6, &mut h7,
                );
                chunk.fill(0);
                chunk[56..].copy_from_slice(&len_bits.to_be_bytes());
                process_chunk(
                    &chunk, &mut h0, &mut h1, &mut h2, &mut h3, &mut h4, &mut h5, &mut h6, &mut h7,
                );
                break;
            }
            _ => unreachable!(),
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
        std::io::BufReader::with_capacity(4096 * 8, std::fs::File::open(&options.path)?);
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
