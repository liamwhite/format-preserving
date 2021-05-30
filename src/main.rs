#![feature(test)]

extern crate rand;
extern crate test;

use ahash::AHasher;
use std::hash::Hasher;

// AES-round based hasher
fn hash_ahash(input: u64) -> u64 {
    let mut hasher = AHasher::new_with_keys(0x5f7788c56cb54593, 0x76fa89eb1eef921d);
    hasher.write_u64(input);
    hasher.finish()
}

// 4-round Feistel network using AES as the round PRF and no key schedule
// Same key is used for each round
fn feistel_evaluate(input: u64, left_bits: u32, right_bits: u32, key: u64) -> u64 {
    let left_mask = (1u64 << left_bits) - 1;
    let right_mask = (1u64 << right_bits) - 1;

    let mut output = input;

    for _ in 0..4 {
        let l = (output >> right_bits) & left_mask;
        let r = output & right_mask;
        let t = (l ^ hash_ahash(r ^ key)) & left_mask;

        output = (r << left_bits) | (t & right_mask);
    }

    output
}

// Format-preserving encryption via cycle-walking for sets of size n
// Returns a random permutation of integers 0..n with no repeats or skips
// Key can be used to influence the generated permutation
fn cycle_walking_fpe(input: u64, n: u64, key: u64) -> u64 {
    let bits = 64 - (n - 1).leading_zeros();
    let left_bits = bits >> 1;
    let right_bits = bits - left_bits;

    let mut output = input;

    loop {
        output = feistel_evaluate(output, left_bits, right_bits, key);

        if output < n {
            break output;
        }
    }
}

fn main() {
    for i in 0..1024 {
        println!("{}", cycle_walking_fpe(i, 1024, hash_ahash(1)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::{Bencher, black_box};

    #[test]
    fn test_bijection_sample() {
        let samples: Vec<u32> = vec![
            16, 461, 161, 324, 879, 104, 820, 742, 783, 795, 735, 619, 217,
            267, 282, 575, 581, 709, 10, 698, 656, 1004, 1005, 467, 445, 787,
            25345, 11322, 10856, 42540, 55356, 10564, 57473, 49024, 8159,
            8337, 47787, 36844, 42002, 39367, 37372, 6872, 29479, 30753,
            10797, 24703, 18836, 51033, 52685, 48931, 23499, 24893,
            500125, 112350, 955974, 1033654, 643440, 577050, 948722, 1045211,
            439513, 390211, 24655, 826485, 1037208, 837007, 614895, 180705,
            850335, 567403, 1033626, 160476, 68020, 558514, 570564, 180353,
            616816, 65537
        ];

        for s in samples {
            let mut v: Vec<u32> = Vec::with_capacity(s as usize);
            let rnd = hash_ahash(1);

            for j in 0..s {
                v.push(cycle_walking_fpe(j as u64, s as u64, rnd) as u32);
            }

            v.sort_unstable();

            // Ensure that the cipher is bijective by sorting it and asserting
            // that the mapping contains everything
            for j in 0..s {
                assert_eq!(j as u32, v[j as usize]);
            }
        }
    }

    #[test]
    fn test_reasonable_entropy() {
        let mut v: Vec<u64> = vec![0; 256];
        let mut p: Vec<f64> = vec![0.; 8];
        let rnd = hash_ahash(1);

        for j in 0..256 {
            v[j] = cycle_walking_fpe(j as u64, 256, rnd);
        }

        // Calculate probability of each bit flipping
        for j in 1..256 {
            let x = v[j] ^ v[j - 1];

            for i in 0..8 {
                p[i] += ((x >> i) & 0x1) as f64 / 256.;
            }
        }

        for i in 0..8 {
            assert!((0.5 - p[i]).abs() < 0.125);
        }
    }

    #[bench]
    fn bench_100_ahash(b: &mut Bencher) {
        let rnd = rand::random::<u64>();

        b.iter(|| {
            let mut x = rnd;

            for _ in 0..100 {
                x = hash_ahash(x);
            }

            black_box(x);
        });
    }

    #[bench]
    fn bench_100_2500000_cycle_walking_fpe(b: &mut Bencher) {
        let key = rand::random::<u64>();

        b.iter(|| {
            for i in 0..100 {
                black_box(cycle_walking_fpe(i, 2_500_000, key));
            }
        });
    }
}
