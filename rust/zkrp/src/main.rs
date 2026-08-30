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
//!   attest-prove <nbits> <cap> <value> <ctx>
//!       -> {"proof_hex", "commit_v_hex", "attestation_hex", "prove_us"}
//!          on success (same failure behavior as `prove`). Implements
//!          HLD.md §7's proposed attestation-bound predicate proof: a mock
//!          enclave attestation (see `attestation.rs`) is generated over
//!          this exact commitment + context, and its digest is absorbed
//!          into the Bulletproofs transcript before any challenge is
//!          drawn -- design only, per §7, until this module's mock is
//!          swapped for a real Nitro/Confidential Space attestation call.
//!   attest-verify <nbits> <cap> <proof_hex> <commit_v_hex> <ctx>
//!                  <attestation_hex> <expected_measurement_hex>
//!       -> {"ok", "reason", "attestation_digest_hex", "measurement_hex",
//!           "verify_us"}. Runs the 6-step chain from HLD.md §7 (steps 1-5;
//!           step 6, appending to the audit log, is the caller's job):
//!           mock cert/signature check, measurement match, nonce
//!           unification, report_data match, then proof verification with
//!           the attestation digest absorbed into the transcript. An empty
//!           <expected_measurement_hex> skips the measurement-match step
//!           (no governance policy configured) without weakening any other
//!           check -- pass "" when the caller has no registered
//!           `prover_measurement` predicate to check against.
//!   attest-measurement -> {"measurement_hex"}: the mock's current PCR0
//!           stand-in, for governance to register as the expected
//!           `prover_measurement` value.
//!   bench  -> JSON micro-benchmarks of the underlying single/aggregate
//!             range proof primitive (unchanged; not cap-aware, this is
//!             raw-primitive feasibility data, see HLD.md/RESULTS.md).

mod attestation;

use attestation::AttestationDoc;
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

/// Like `transcript`, but also absorbs the attestation document's digest
/// (direction B of HLD.md §7's mutual binding) before any Fiat-Shamir
/// challenge is drawn -- a proof built against one attestation cannot be
/// re-presented alongside a different one.
fn transcript_attested(context: &str, attestation_digest: &[u8; 32]) -> Transcript {
    let mut t = transcript(context);
    t.append_message(b"attestation", attestation_digest);
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

#[derive(Debug, PartialEq, Eq)]
pub enum ProveError {
    /// value > cap, or value/d does not fit in nbits. The prover must
    /// refuse rather than emit a proof for a false statement.
    PredicateViolated,
}

#[derive(Debug)]
pub struct ProveOutput {
    pub proof_hex: String,
    pub commit_v_hex: String,
    pub prove_us: f64,
}

pub struct VerifyOutput {
    pub ok: bool,
    pub verify_us: f64,
}

/// Pure core of `prove`: no I/O, no process::exit, so it's directly unit
/// testable. cmd_prove (below) is the thin CLI wrapper.
fn prove_range_leq(nbits: usize, cap: u64, value: u64, ctx: &str) -> Result<ProveOutput, ProveError> {
    let d = cap.checked_sub(value).ok_or(ProveError::PredicateViolated)?;
    let max = if nbits >= 64 { u64::MAX } else { (1u64 << nbits) - 1 };
    if value > max || d > max {
        return Err(ProveError::PredicateViolated);
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

    Ok(ProveOutput {
        proof_hex: hex::encode(proof.to_bytes()),
        commit_v_hex: hex::encode(commits[0].as_bytes()),
        prove_us: us,
    })
}

/// Pure core of `verify`: no I/O, directly unit testable. Never trusts a
/// prover-supplied d commitment -- always re-derives C_d = cap*B - C_v.
fn verify_range_leq(nbits: usize, cap: u64, proof_hex: &str, commit_v_hex: &str, ctx: &str) -> VerifyOutput {
    let pc = PedersenGens::default();
    let bp = BulletproofGens::new(nbits, 2);

    let proof = match hex::decode(proof_hex).ok().and_then(|b| RangeProof::from_bytes(&b).ok()) {
        Some(p) => p,
        None => return VerifyOutput { ok: false, verify_us: 0.0 },
    };
    let commit_v_bytes = match hex::decode(commit_v_hex) {
        Ok(b) => b,
        Err(_) => return VerifyOutput { ok: false, verify_us: 0.0 },
    };
    let commit_v = CompressedRistretto::from_slice(&commit_v_bytes);
    let commit_v_point = match commit_v.decompress() {
        Some(p) => p,
        None => return VerifyOutput { ok: false, verify_us: 0.0 },
    };
    let commit_d = (cap_point(&pc, cap) - commit_v_point).compress();

    let t0 = Instant::now();
    let ok = proof
        .verify_multiple(&bp, &pc, &mut transcript(ctx), &[commit_v, commit_d], nbits)
        .is_ok();
    let us = t0.elapsed().as_secs_f64() * 1e6;
    VerifyOutput { ok, verify_us: us }
}

#[derive(Debug)]
pub struct AttestedProveOutput {
    pub proof_hex: String,
    pub commit_v_hex: String,
    pub attestation_hex: String,
    pub prove_us: f64,
}

pub struct AttestedVerifyOutput {
    pub ok: bool,
    pub reason: String,
    pub attestation_digest_hex: String,
    pub measurement_hex: String,
    pub verify_us: f64,
}

fn attested_fail(reason: &str) -> AttestedVerifyOutput {
    AttestedVerifyOutput {
        ok: false,
        reason: reason.to_string(),
        attestation_digest_hex: String::new(),
        measurement_hex: String::new(),
        verify_us: 0.0,
    }
}

/// Attested variant of `prove_range_leq`: same statement and same validity
/// checks, but additionally produces a mock enclave attestation over the
/// value commitment and absorbs its digest into the transcript before
/// drawing challenges. See HLD.md §7.
fn prove_range_leq_attested(
    nbits: usize,
    cap: u64,
    value: u64,
    ctx: &str,
) -> Result<AttestedProveOutput, ProveError> {
    let d = cap.checked_sub(value).ok_or(ProveError::PredicateViolated)?;
    let max = if nbits >= 64 { u64::MAX } else { (1u64 << nbits) - 1 };
    if value > max || d > max {
        return Err(ProveError::PredicateViolated);
    }

    let pc = PedersenGens::default();
    let bp = BulletproofGens::new(nbits, 2);
    let mut rng = thread_rng();
    let r_v = Scalar::random(&mut rng);
    let r_d = -r_v;

    // C_v must exist before the attestation is generated (report_data
    // commits to it, direction A) and before the transcript is built (the
    // transcript must absorb the attestation before any challenge is
    // drawn, direction B) -- this ordering is the crux of the protocol,
    // not the hashing itself.
    let commit_v = pc.commit(Scalar::from(value), r_v).compress();
    let doc = AttestationDoc::generate(commit_v.as_bytes(), ctx);
    let doc_digest = doc.digest();

    let t0 = Instant::now();
    let (proof, commits) = RangeProof::prove_multiple(
        &bp,
        &pc,
        &mut transcript_attested(ctx, &doc_digest),
        &[value, d],
        &[r_v, r_d],
        nbits,
    )
    .expect("prove_multiple");
    let us = t0.elapsed().as_secs_f64() * 1e6;
    debug_assert_eq!(commits[0], commit_v);

    Ok(AttestedProveOutput {
        proof_hex: hex::encode(proof.to_bytes()),
        commit_v_hex: hex::encode(commit_v.as_bytes()),
        attestation_hex: doc.to_hex(),
        prove_us: us,
    })
}

/// Attested variant of `verify_range_leq`: runs the 6-step chain from
/// HLD.md §7 (steps 1-5; step 6 is the caller appending to the audit log).
/// Never trusts a prover-supplied d commitment, exactly like the
/// unattested path -- C_d is always re-derived homomorphically.
fn verify_range_leq_attested(
    nbits: usize,
    cap: u64,
    proof_hex: &str,
    commit_v_hex: &str,
    ctx: &str,
    attestation_hex: &str,
    expected_measurement_hex: &str,
) -> AttestedVerifyOutput {
    let pc = PedersenGens::default();
    let bp = BulletproofGens::new(nbits, 2);

    let proof = match hex::decode(proof_hex).ok().and_then(|b| RangeProof::from_bytes(&b).ok()) {
        Some(p) => p,
        None => return attested_fail("malformed proof"),
    };
    let commit_v_bytes = match hex::decode(commit_v_hex) {
        Ok(b) => b,
        Err(_) => return attested_fail("malformed commitment"),
    };
    let commit_v = CompressedRistretto::from_slice(&commit_v_bytes);
    let commit_v_point = match commit_v.decompress() {
        Some(p) => p,
        None => return attested_fail("invalid commitment point"),
    };
    let commit_d = (cap_point(&pc, cap) - commit_v_point).compress();

    let doc = match AttestationDoc::from_hex(attestation_hex) {
        Some(d) => d,
        None => return attested_fail("malformed attestation"),
    };

    // Step 1 (mock): stands in for validating the attestation's
    // certificate chain to the platform root.
    if !doc.verify_signature() {
        return attested_fail("attestation signature invalid");
    }
    // Step 2: measurement must match the governance-registered value, when
    // governance has registered one. An empty expected_measurement_hex
    // means no `prover_measurement` predicate is configured for this
    // deployment -- the attestation is still fully validated (signature,
    // nonce, report_data, transcript), just not policed against a specific
    // expected binary. This is what lets a prover that always attests
    // (HLD.md §7's `attest-prove`) interoperate with a gateway that hasn't
    // opted into measurement enforcement.
    if !expected_measurement_hex.is_empty() {
        let expected_measurement: [u8; 48] = match hex::decode(expected_measurement_hex) {
            Ok(b) if b.len() == 48 => b.as_slice().try_into().unwrap(),
            _ => return attested_fail("malformed expected measurement"),
        };
        if !doc.check_measurement(&expected_measurement) {
            return attested_fail("prover measurement mismatch");
        }
    }
    // Step 3: nonce unification -- attestation freshness checked against
    // this exact request context.
    if !doc.check_nonce(ctx) {
        return attested_fail("attestation nonce does not match request context");
    }
    // Step 4: report_data must commit to this exact proof commitment.
    if !doc.check_report_data(commit_v.as_bytes(), ctx) {
        return attested_fail("report_data does not match commitment");
    }

    // Step 5: verify the proof with the attestation digest absorbed into
    // the transcript -- a proof cannot be presented under a substituted
    // attestation.
    let doc_digest = doc.digest();
    let t0 = Instant::now();
    let ok = proof
        .verify_multiple(&bp, &pc, &mut transcript_attested(ctx, &doc_digest), &[commit_v, commit_d], nbits)
        .is_ok();
    let us = t0.elapsed().as_secs_f64() * 1e6;
    if !ok {
        return attested_fail("proof verification failed");
    }

    AttestedVerifyOutput {
        ok: true,
        reason: String::new(),
        attestation_digest_hex: hex::encode(doc_digest),
        measurement_hex: hex::encode(doc.measurement),
        verify_us: us,
    }
}

fn cmd_prove(nbits: usize, cap: u64, value: u64, ctx: &str) {
    match prove_range_leq(nbits, cap, value, ctx) {
        Ok(out) => println!(
            "{{\"proof_hex\": \"{}\", \"commit_v_hex\": \"{}\", \"prove_us\": {:.0}}}",
            out.proof_hex, out.commit_v_hex, out.prove_us
        ),
        Err(ProveError::PredicateViolated) => {
            println!("{{\"error\": \"predicate violated\"}}");
            std::process::exit(1);
        }
    }
}

fn cmd_verify(nbits: usize, cap: u64, proof_hex: &str, commit_v_hex: &str, ctx: &str) {
    let out = verify_range_leq(nbits, cap, proof_hex, commit_v_hex, ctx);
    println!("{{\"ok\": {}, \"verify_us\": {:.0}}}", out.ok, out.verify_us);
}

fn cmd_attest_prove(nbits: usize, cap: u64, value: u64, ctx: &str) {
    match prove_range_leq_attested(nbits, cap, value, ctx) {
        Ok(out) => println!(
            "{{\"proof_hex\": \"{}\", \"commit_v_hex\": \"{}\", \"attestation_hex\": \"{}\", \"prove_us\": {:.0}}}",
            out.proof_hex, out.commit_v_hex, out.attestation_hex, out.prove_us
        ),
        Err(ProveError::PredicateViolated) => {
            println!("{{\"error\": \"predicate violated\"}}");
            std::process::exit(1);
        }
    }
}

fn cmd_attest_verify(
    nbits: usize,
    cap: u64,
    proof_hex: &str,
    commit_v_hex: &str,
    ctx: &str,
    attestation_hex: &str,
    expected_measurement_hex: &str,
) {
    let out = verify_range_leq_attested(
        nbits, cap, proof_hex, commit_v_hex, ctx, attestation_hex, expected_measurement_hex,
    );
    println!(
        "{{\"ok\": {}, \"reason\": \"{}\", \"attestation_digest_hex\": \"{}\", \"measurement_hex\": \"{}\", \"verify_us\": {:.0}}}",
        out.ok, out.reason, out.attestation_digest_hex, out.measurement_hex, out.verify_us
    );
}

fn cmd_attest_measurement() {
    println!("{{\"measurement_hex\": \"{}\"}}", hex::encode(attestation::current_measurement()));
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
        Some("attest-prove") => {
            let n: usize = args[2].parse().unwrap();
            let cap: u64 = args[3].parse().unwrap();
            let v: u64 = args[4].parse().unwrap();
            let ctx = args.get(5).cloned().unwrap_or_default();
            cmd_attest_prove(n, cap, v, &ctx);
        }
        Some("attest-verify") => {
            let n: usize = args[2].parse().unwrap();
            let cap: u64 = args[3].parse().unwrap();
            let proof_hex = &args[4];
            let commit_v_hex = &args[5];
            let ctx = args.get(6).cloned().unwrap_or_default();
            let attestation_hex = args.get(7).cloned().unwrap_or_default();
            let expected_measurement_hex = args.get(8).cloned().unwrap_or_default();
            cmd_attest_verify(n, cap, proof_hex, commit_v_hex, &ctx, &attestation_hex, &expected_measurement_hex);
        }
        Some("attest-measurement") => cmd_attest_measurement(),
        _ => eprintln!(
            "usage: zkrp bench\n\
             \x20      | prove <nbits> <cap> <value> [ctx]\n\
             \x20      | verify <nbits> <cap> <proof_hex> <commit_v_hex> [ctx]\n\
             \x20      | attest-prove <nbits> <cap> <value> <ctx>\n\
             \x20      | attest-verify <nbits> <cap> <proof_hex> <commit_v_hex> <ctx> <attestation_hex> <expected_measurement_hex>\n\
             \x20      | attest-measurement"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAP: u64 = 1_000_000_000;
    const NBITS: usize = 32;

    #[test]
    fn honest_roundtrip_verifies() {
        let out = prove_range_leq(NBITS, CAP, 735_000_000, "ctxA").expect("should prove");
        let v = verify_range_leq(NBITS, CAP, &out.proof_hex, &out.commit_v_hex, "ctxA");
        assert!(v.ok);
    }

    #[test]
    fn tampered_proof_rejected() {
        let out = prove_range_leq(NBITS, CAP, 735_000_000, "ctxA").unwrap();
        let mut bytes = hex::decode(&out.proof_hex).unwrap();
        bytes[10] ^= 0xff;
        let tampered = hex::encode(bytes);
        let v = verify_range_leq(NBITS, CAP, &tampered, &out.commit_v_hex, "ctxA");
        assert!(!v.ok);
    }

    #[test]
    fn wrong_context_rejected() {
        let out = prove_range_leq(NBITS, CAP, 735_000_000, "ctxA").unwrap();
        let v = verify_range_leq(NBITS, CAP, &out.proof_hex, &out.commit_v_hex, "ctxB");
        assert!(!v.ok);
    }

    #[test]
    fn cap_lowered_at_verify_time_rejected() {
        let out = prove_range_leq(NBITS, CAP, 735_000_000, "ctxA").unwrap();
        let v = verify_range_leq(NBITS, 100_000_000, &out.proof_hex, &out.commit_v_hex, "ctxA");
        assert!(!v.ok);
    }

    #[test]
    fn over_cap_value_refuses_to_prove() {
        let err = prove_range_leq(NBITS, CAP, 1_250_000_000, "ctxC").unwrap_err();
        assert_eq!(err, ProveError::PredicateViolated);
    }

    #[test]
    fn value_exceeding_bit_width_refuses_to_prove() {
        // A value that comfortably satisfies value <= cap but doesn't fit
        // in nbits must still be refused -- proving v<=cap alone isn't the
        // full statement; v (and d) must also be valid n-bit integers.
        let err = prove_range_leq(8, u64::MAX, 1000, "ctxD").unwrap_err();
        assert_eq!(err, ProveError::PredicateViolated);
    }

    #[test]
    fn malformed_hex_rejected_not_panicking() {
        let v = verify_range_leq(NBITS, CAP, "not-hex", "e6b7e9a9", "ctxA");
        assert!(!v.ok);
    }

    // ---------------------------------------------------- attested variant

    fn expected_measurement_hex() -> String {
        hex::encode(attestation::current_measurement())
    }

    #[test]
    fn attested_honest_roundtrip_verifies() {
        let out = prove_range_leq_attested(NBITS, CAP, 735_000_000, "ctxA").expect("should prove");
        let v = verify_range_leq_attested(
            NBITS, CAP, &out.proof_hex, &out.commit_v_hex, "ctxA", &out.attestation_hex,
            &expected_measurement_hex(),
        );
        assert!(v.ok, "reason={}", v.reason);
        assert!(!v.attestation_digest_hex.is_empty());
        assert_eq!(v.measurement_hex, expected_measurement_hex());
    }

    #[test]
    fn attested_empty_expected_measurement_skips_the_check() {
        // No prover_measurement predicate registered (empty expected hex)
        // -- attestation must still be fully validated, just not policed
        // against a specific measurement. This is what lets a prover that
        // always attests interoperate with a gateway that hasn't opted
        // into measurement enforcement.
        let out = prove_range_leq_attested(NBITS, CAP, 735_000_000, "ctxA").unwrap();
        let v = verify_range_leq_attested(
            NBITS, CAP, &out.proof_hex, &out.commit_v_hex, "ctxA", &out.attestation_hex, "",
        );
        assert!(v.ok, "reason={}", v.reason);
    }

    #[test]
    fn attested_wrong_measurement_rejected() {
        let out = prove_range_leq_attested(NBITS, CAP, 735_000_000, "ctxA").unwrap();
        let bogus_measurement = hex::encode([0u8; 48]);
        let v = verify_range_leq_attested(
            NBITS, CAP, &out.proof_hex, &out.commit_v_hex, "ctxA", &out.attestation_hex,
            &bogus_measurement,
        );
        assert!(!v.ok);
        assert_eq!(v.reason, "prover measurement mismatch");
    }

    #[test]
    fn attested_tampered_attestation_signature_rejected() {
        let out = prove_range_leq_attested(NBITS, CAP, 735_000_000, "ctxA").unwrap();
        let mut bytes = hex::decode(&out.attestation_hex).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff; // flip a byte inside the trailing signature
        let tampered = hex::encode(bytes);
        let v = verify_range_leq_attested(
            NBITS, CAP, &out.proof_hex, &out.commit_v_hex, "ctxA", &tampered,
            &expected_measurement_hex(),
        );
        assert!(!v.ok);
        assert_eq!(v.reason, "attestation signature invalid");
    }

    #[test]
    fn attested_nonce_mismatch_rejected() {
        // Verifying under a different context than the one the attestation
        // (and proof transcript) were generated for must fail nonce
        // unification before it ever reaches proof verification.
        let out = prove_range_leq_attested(NBITS, CAP, 735_000_000, "ctxA").unwrap();
        let v = verify_range_leq_attested(
            NBITS, CAP, &out.proof_hex, &out.commit_v_hex, "ctxB", &out.attestation_hex,
            &expected_measurement_hex(),
        );
        assert!(!v.ok);
        assert_eq!(v.reason, "attestation nonce does not match request context");
    }

    #[test]
    fn attested_swapped_attestation_rejected() {
        // An attacker pairs a fresh, validly-signed attestation (for a
        // DIFFERENT proof/commitment) with this proof. report_data must
        // catch the substitution even though the attestation itself is
        // genuine and its nonce/context matches.
        let out_a = prove_range_leq_attested(NBITS, CAP, 100_000_000, "ctxA").unwrap();
        let out_b = prove_range_leq_attested(NBITS, CAP, 200_000_000, "ctxA").unwrap();
        let v = verify_range_leq_attested(
            NBITS, CAP, &out_a.proof_hex, &out_a.commit_v_hex, "ctxA", &out_b.attestation_hex,
            &expected_measurement_hex(),
        );
        assert!(!v.ok);
        // Whichever check fails first (report_data, or the transcript
        // absorbing a mismatched attestation digest), it must not verify.
        assert!(!v.reason.is_empty());
    }

    #[test]
    fn attested_tampered_proof_rejected() {
        let out = prove_range_leq_attested(NBITS, CAP, 735_000_000, "ctxA").unwrap();
        let mut bytes = hex::decode(&out.proof_hex).unwrap();
        bytes[10] ^= 0xff;
        let tampered = hex::encode(bytes);
        let v = verify_range_leq_attested(
            NBITS, CAP, &tampered, &out.commit_v_hex, "ctxA", &out.attestation_hex,
            &expected_measurement_hex(),
        );
        assert!(!v.ok);
    }

    #[test]
    fn attested_malformed_attestation_rejected_not_panicking() {
        let out = prove_range_leq_attested(NBITS, CAP, 735_000_000, "ctxA").unwrap();
        let v = verify_range_leq_attested(
            NBITS, CAP, &out.proof_hex, &out.commit_v_hex, "ctxA", "not-hex",
            &expected_measurement_hex(),
        );
        assert!(!v.ok);
        assert_eq!(v.reason, "malformed attestation");
    }
}
