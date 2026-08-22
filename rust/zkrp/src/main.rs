//! zkrp: Bulletproofs range-proof engine for the ZK Proof Gateway prototype.
//!
//! Statement: PoK{(v, r): C = v*B + r*B_blind  AND  v in [0, 2^n)}
//! For the gateway's `range_leq` predicate (v <= cap) the standard reduction
//! is proving BOTH v in [0,2^n) and (cap - v) in [0,2^n) over homomorphic
//! commitments, i.e. the same asymptotics at roughly twice the cost of one
//! proof (or one 2-aggregate).
//!
//! Subcommands:
//!   prove <nbits> <value>            -> proof+commitment (hex) + timing
//!   verify <nbits> <proof_hex> <commit_hex> [context]
//!   bench                            -> JSON micro-benchmarks incl. aggregation

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;
use std::time::Instant;

fn transcript(context: &str) -> Transcript {
    let mut t = Transcript::new(b"zkgw/bulletproofs/v1");
    t.append_message(b"context", context.as_bytes());
    t
}

fn median(mut xs: Vec<f64>) -> f64 {
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    xs[xs.len() / 2]
}

fn bench() {
    let pc = PedersenGens::default();
    let bp = BulletproofGens::new(64, 16);
    let mut rng = thread_rng();
    let iters = 30;

    println!("{{");
    println!("  \"engine\": \"bulletproofs-dalek-ristretto255 (rust 1.75, opt3+lto)\",");
    println!("  \"single\": [");
    let widths = [8usize, 16, 32, 64];
    for (wi, &n) in widths.iter().enumerate() {
        let v: u64 = if n == 64 { 735_000_000 } else { (1u64 << (n - 1)) - 3 };
        let mut pt = vec![];
        let mut vt = vec![];
        let mut size = 0usize;
        for _ in 0..iters {
            let blind = Scalar::random(&mut rng);
            let t0 = Instant::now();
            let (proof, commit) =
                RangeProof::prove_single(&bp, &pc, &mut transcript("bench"), v, &blind, n)
                    .expect("prove");
            let prove_us = t0.elapsed().as_secs_f64() * 1e6;
            size = proof.to_bytes().len();
            let t1 = Instant::now();
            proof
                .verify_single(&bp, &pc, &mut transcript("bench"), &commit, n)
                .expect("verify");
            let verify_us = t1.elapsed().as_secs_f64() * 1e6;
            pt.push(prove_us);
            vt.push(verify_us);
        }
        println!(
            "    {{\"nbits\": {}, \"proof_bytes\": {}, \"prove_us_med\": {:.0}, \"verify_us_med\": {:.0}}}{}",
            n, size, median(pt), median(vt),
            if wi + 1 < widths.len() { "," } else { "" }
        );
    }
    println!("  ],");

    // Aggregation: m proofs of 64-bit values in ONE aggregated proof
    println!("  \"aggregated_64bit\": [");
    let ms = [1usize, 2, 4, 8, 16];
    for (mi, &m) in ms.iter().enumerate() {
        let values: Vec<u64> = (0..m).map(|i| 1_000_000 + i as u64).collect();
        let blinds: Vec<Scalar> = (0..m).map(|_| Scalar::random(&mut rng)).collect();
        let mut pt = vec![];
        let mut vt = vec![];
        let mut size = 0usize;
        for _ in 0..10 {
            let t0 = Instant::now();
            let (proof, commits) = RangeProof::prove_multiple(
                &bp, &pc, &mut transcript("bench-agg"), &values, &blinds, 64,
            )
            .expect("prove_multiple");
            let prove_us = t0.elapsed().as_secs_f64() * 1e6;
            size = proof.to_bytes().len();
            let t1 = Instant::now();
            proof
                .verify_multiple(&bp, &pc, &mut transcript("bench-agg"), &commits, 64)
                .expect("verify_multiple");
            let verify_us = t1.elapsed().as_secs_f64() * 1e6;
            pt.push(prove_us);
            vt.push(verify_us);
        }
        println!(
            "    {{\"m\": {}, \"proof_bytes\": {}, \"prove_us_med\": {:.0}, \"verify_us_med\": {:.0}}}{}",
            m, size, median(pt), median(vt),
            if mi + 1 < ms.len() { "," } else { "" }
        );
    }
    println!("  ]");
    println!("}}");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("bench") => bench(),
        Some("prove") => {
            let n: usize = args[2].parse().unwrap();
            let v: u64 = args[3].parse().unwrap();
            let ctx = args.get(4).cloned().unwrap_or_default();
            let pc = PedersenGens::default();
            let bp = BulletproofGens::new(64, 1);
            let blind = Scalar::random(&mut thread_rng());
            let t0 = Instant::now();
            let (proof, commit) =
                RangeProof::prove_single(&bp, &pc, &mut transcript(&ctx), v, &blind, n)
                    .expect("prove");
            let us = t0.elapsed().as_secs_f64() * 1e6;
            println!(
                "{{\"proof_hex\": \"{}\", \"commit_hex\": \"{}\", \"prove_us\": {:.0}}}",
                hex::encode(proof.to_bytes()),
                hex::encode(commit.as_bytes()),
                us
            );
        }
        Some("verify") => {
            let n: usize = args[2].parse().unwrap();
            let proof = RangeProof::from_bytes(&hex::decode(&args[3]).unwrap()).unwrap();
            let commit = curve25519_dalek_ng::ristretto::CompressedRistretto::from_slice(
                &hex::decode(&args[4]).unwrap(),
            );
            let ctx = args.get(5).cloned().unwrap_or_default();
            let pc = PedersenGens::default();
            let bp = BulletproofGens::new(64, 1);
            let t0 = Instant::now();
            let ok = proof
                .verify_single(&bp, &pc, &mut transcript(&ctx), &commit, n)
                .is_ok();
            let us = t0.elapsed().as_secs_f64() * 1e6;
            println!("{{\"ok\": {}, \"verify_us\": {:.0}}}", ok, us);
        }
        _ => eprintln!("usage: zkrp bench | prove <n> <v> [ctx] | verify <n> <proof> <commit> [ctx]"),
    }
}
