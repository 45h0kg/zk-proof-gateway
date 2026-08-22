"""Adversarial experiments (paper Section VI, 'experimentation proof').

Each test models a concrete attacker from the threat model:
  T1  malicious prover: value > cap, tries to submit a proof for a smaller value
      but is bound by the homomorphic consistency check
  T2  bit-flip tampering of a serialized proof in transit
  T3  replay of a valid proof under a different request context (nonce)
  T4  replay under a different predicate version (policy changed)
  T5  compromised agent tries to publish its own loose predicate (unsigned /
      wrong key) to the registry
  T6  post-hoc audit-log tampering (hash chain must detect)
  T7  malicious prover constructs bit commitments with a non-binary 'bit'
      (e.g. 2) to overflow the range; the OR-proof must be unforgeable
"""
import base64, copy, json, random, secrets
from zkgw.curve import G, H, N
from zkgw.primitives import rand_scalar, sign, Transcript, commit
from zkgw import rangeproof
from zkgw.rangeproof import prove_range_leq, verify_range_leq, BitOrProof
from zkgw.gateway import (
    Predicate, PredicateRegistry, AuditLog, ProofGateway,
    ExecutionAgent, RiskAgent, serialize_proof, deserialize_proof, make_envelope,
)

random.seed(1337)
CAP, NBITS = 1_000_000_000, 32
CTX = {"nonce": "n-001", "request_id": "r-001", "predicate_id": "pretrade_notional_cap",
       "predicate_version": 1, "requester": "risk-agent-01", "prover": "exec-agent-07",
       "ts": 1750000000}
results = []

def check(name, expect, got):
    ok = expect == got
    results.append((name, ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: expected {expect}, got {got}")

print("T0  honest baseline")
proof = prove_range_leq(735_000_000, CAP, NBITS, CTX)
check("valid proof verifies", True, verify_range_leq(proof, CAP, CTX))

print("T1  malicious prover with value > cap")
try:
    prove_range_leq(1_250_000_000, CAP, NBITS, CTX)
    check("honest API refuses out-of-range", True, False)
except ValueError:
    check("honest API refuses out-of-range", True, True)
# forging path: prove a DIFFERENT (in-range) value, then claim it was the real
# notional, but the commitment in the audit log binds the proof to what was
# proved; the source-of-truth fetch happens gateway-side in deployment A
# (see HLD threat discussion). Cryptographic forging of v>cap is tested in T7.

print("T2  bit-flip tampering in transit")
raw = bytearray(serialize_proof(proof))
obj = json.loads(bytes(raw))
obj["Pv"][3]["z0"] = hex(int(obj["Pv"][3]["z0"], 16) ^ 1)
tampered = deserialize_proof(json.dumps(obj).encode())
check("tampered response scalar rejected", False, verify_range_leq(tampered, CAP, CTX))
obj2 = json.loads(serialize_proof(proof))
obj2["Cv"][0], obj2["Cv"][1] = obj2["Cv"][1], obj2["Cv"][0]
swapped = deserialize_proof(json.dumps(obj2).encode())
check("swapped bit commitments rejected", False, verify_range_leq(swapped, CAP, CTX))

print("T3  replay under different nonce")
check("cross-nonce replay rejected", False,
      verify_range_leq(proof, CAP, dict(CTX, nonce="n-999")))

print("T4  replay under different predicate version")
check("cross-version replay rejected", False,
      verify_range_leq(proof, CAP, dict(CTX, predicate_version=2)))

print("T5  compromised agent publishes its own predicate")
gov_secret = rand_scalar(); gov_pub = gov_secret * G
reg = PredicateRegistry(gov_pub)
rogue = Predicate("pretrade_notional_cap", 99, "range_leq",
                  {"cap": 2**31, "nbits": 32, "unit": "USD_cents"}, "exec-agent-07")
try:
    reg.publish(rogue); check("unsigned predicate rejected", True, False)
except PermissionError:
    check("unsigned predicate rejected", True, True)
attacker_key = rand_scalar()
rogue.signature = sign(attacker_key, rogue.canonical_bytes())
try:
    reg.publish(rogue); check("wrong-key predicate rejected", True, False)
except PermissionError:
    check("wrong-key predicate rejected", True, True)

print("T6  audit-log tampering")
audit = AuditLog("/tmp/audit_t6.jsonl")
gw_pred = Predicate("pretrade_notional_cap", 1, "range_leq",
                    {"cap": CAP, "nbits": NBITS, "unit": "USD_cents"}, "gov")
gw_pred.signature = sign(gov_secret, gw_pred.canonical_bytes())
reg.publish(gw_pred)
gw = ProofGateway(reg, audit)
agent = ExecutionAgent("exec-agent-07", 735_000_000)
risk = RiskAgent("risk-agent-01", gw)
for _ in range(3):
    risk.check_pretrade(agent, "pretrade_notional_cap", 1)
check("untouched chain verifies", True, AuditLog.verify_chain(audit.path))
lines = open(audit.path).read().splitlines()
rec = json.loads(lines[1]); rec["result"] = "PASS_EDITED"
lines[1] = json.dumps(rec, sort_keys=True)
open("/tmp/audit_t6_tampered.jsonl", "w").write("\n".join(lines) + "\n")
check("edited entry detected", False, AuditLog.verify_chain("/tmp/audit_t6_tampered.jsonl"))

print("T7  forged non-binary 'bit' (value overflow attempt)")
# Attacker commits C = 2*G + r*H for one bit position (would encode value 2^i * 2)
# and tries to fake the OR-proof for it with random responses.
forged = prove_range_leq(735_000_000, CAP, NBITS, CTX)
r_evil = rand_scalar()
evil_C = commit(2, r_evil)
attempts, success = 2000, 0
for _ in range(attempts):
    fake = BitOrProof(rand_scalar() * H, rand_scalar() * H,
                      rand_scalar(), rand_scalar(), rand_scalar())
    f2 = copy.copy(forged)
    f2.bit_commitments_v = list(forged.bit_commitments_v); f2.bit_commitments_v[0] = evil_C
    f2.bit_proofs_v = list(forged.bit_proofs_v); f2.bit_proofs_v[0] = fake
    if verify_range_leq(f2, CAP, CTX):
        success += 1
check(f"random forgery attempts succeeding (n={attempts})", 0, success)

print()
passed = sum(1 for _, ok in results if ok)
print(f"SOUNDNESS SUITE: {passed}/{len(results)} checks passed")
assert passed == len(results)
