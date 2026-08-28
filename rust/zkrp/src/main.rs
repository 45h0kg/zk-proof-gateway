//! zkrp: Bulletproofs range-proof engine for the ZK Proof Gateway prototype.
//!
//! Statement for the gateway's `range_leq` predicate: PoK{(v, r): C_v = v*B +
//! r*B_blind AND 0 <= v <= cap}. Constructed via the standard reduction: let
//! d = cap - v; prove BOTH v and d lie in [0, 2^n) as ONE 2-aggregate
//! Bulletproof (same transcript, same asymptotics as a single proof at
//! roughly double the constraint count). The verifier never trusts a
//! prover-supplied commitment to d -- it derives C_d = cap*B - C_v itself
//! homomorphically, exactly mirroring the Python E1 engine's construction
//! (rangeproof.py). This is what actually enforces the cap; proving `v`
//! alone fits in `n` bits (the previous version of this file) does not.
//!
//! Subcommands:
//!   prove <nbits> <cap> <value> [ctx]
//!       -> {"proof_hex", "commit_v_hex", "prove_us"} on success.
//!       -> {"error": "predicate violated"} + nonzero exit if value > cap
//!          or value/cap do not fit in nbits. Never emits a proof for a
//!          false statement.
//!   verify <nbits> <cap> <proof_hex> <commit_v_hex> [ctx]
//!       -> {"ok", "verify_us"}
//!   bench  -> JSON micro-benchmarks of the underlying single/aggregate
//!             range proof primitive (unchanged; not cap-aware, this is
//!             raw-primitive feasibility data, see HLD.md/RESULTS.md).

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::ristretto::CompressedRistretto;
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

/// cap_point = cap * B, the value-generator, used to homomorphically derive
/// C_d = cap*B - C_v without ever trusting a prover-supplied d commitment.
fn cap_point(pc: &PedersenGens, cap: u64) -> curve25519_dalek_ng::ristretto::RistrettoPoint {
    Scalar::from(cap) * pc.B
}

fn cmd_prove(nbits: usize, cap: u64, value: u64, ctx: &str) {
    let d = match cap.checked_sub(value) {
        Some(d) => d,
        None => {
            println!("{{\"error\": \"predicate violated\"}}");
            std::process::exit(1);
        }
    };
    // Both v and d must fit in nbits for the aggregate range proof to even
    // be constructible; out-of-width values are also a predicate violation.
    let max = if nbits >= 64 { u64::MAX } else { (1u64 << nbits) - 1 };
    if value > max || d > max {
        println!("{{\"error\": \"predicate violated\"}}");
        std::process::exit(1);
    }

    let pc = PedersenGens::default();
    let bp = BulletproofGens::new(nbits, 2);
    let mut rng = thread_rng();
    let r_v = Scalar::random(&mut rng);
    let r_d = -r_v; // so Commit(v, r_v) + Commit(d, r_d) == cap*B, exactly

    let t0 = Instant::now();
    let (proof, commits) = RangeProof::prove_multiple(
        &bp, &pc, &mut transcript(ctx), &[value, d], &[r_v, r_d], nbits,
    )
    .expect("prove_multiple");
    let us = t0.elapsed().as_secs_f64() * 1e6;

    println!(
        "{{\"proof_hex\": \"{}\", \"commit_v_hex\": \"{}\", \"prove_us\": {:.0}}}",
        hex::encode(proof.to_bytes()),
        hex::encode(commits[0].as_bytes()),
        us
    );
}

fn cmd_verify(nbits: usize, cap: u64, proof_hex: &str, commit_v_hex: &str, ctx: &str) {
    let pc = PedersenGens::default();
    let bp = BulletproofGens::new(nbits, 2);

    let proof = match RangeProof::from_bytes(&hex::decode(proof_hex).unwrap()) {
        Ok(p) => p,
        Err(_) => {
            println!("{{\"ok\": false, \"verify_us\": 0}}");
            return;
        }
    };
    let commit_v_bytes = hex::decode(commit_v_hex).unwrap();
    let commit_v = CompressedRistretto::from_slice(&commit_v_bytes);

    let commit_v_point = match commit_v.decompress() {
        Some(p) => p,
        None => {
            println!("{{\"ok\": false, \"verify_us\": 0}}");
            return;
        }
    };
    // Derive C_d ourselves -- never trust a prover-supplied d commitment.
    let commit_d = (cap_point(&pc, cap) - commit_v_point).compress();

    let t0 = Instant::now();
    let ok = proof
        .verify_multiple(&bp, &pc, &mut transcript(ctx), &[commit_v, commit_d], nbits)
        .is_ok();
    let us = t0.elapsed().as_secs_f64() * 1e6;
    println!("{{\"ok\": {}, \"verify_us\": {:.0}}}", ok, us);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("bench") => bench(),
        Some("prove") => {
            let n: usize = args[2].parse().unwrap();
            let cap: u64 = args[3].parse().unwrap();
            let v: u64 = args[4].parse().unwrap();
            let ctx = args.get(5).cloned().unwrap_or_default();
            cmd_prove(n, cap, v, &ctx);
        }
        Some("verify") => {
            let n: usize = args[2].parse().unwrap();
            let cap: u64 = args[3].parse().unwrap();
            let proof_hex = &args[4];
            let commit_v_hex = &args[5];
            let ctx = args.get(6).cloned().unwrap_or_default();
            cmd_verify(n, cap, proof_hex, commit_v_hex, &ctx);
        }
        _ => eprintln!(
            "usage: zkrp bench | prove <nbits> <cap> <value> [ctx] | verify <nbits> <cap> <proof_hex> <commit_v_hex> [ctx]"
        ),
    }
}
