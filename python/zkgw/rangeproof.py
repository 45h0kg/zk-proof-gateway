"""Zero-knowledge range and threshold proofs (pure-Python baseline engine).

Statement proved for the gateway's `range_leq` predicate:

    PoK{ (v, r) :  C_v = v*G + r*H   AND   0 <= v <= cap }

Construction (classical bit-decomposition, O(n) proof size):
  1. Commit to each bit of v:      C_i = b_i*G + r_i*H
  2. Prove each C_i commits to 0 or 1 with a CDS OR-composition of two
     Schnorr proofs (Cramer-Damgard-Schoenmakers, CRYPTO '94), made
     non-interactive with a single Fiat-Shamir challenge.
  3. The value commitment is C_v = sum_i 2^i * C_i (verifier recomputes it),
     so C_v = v*G + r_v*H with r_v = sum_i 2^i r_i.
  4. For v <= cap: let d = cap - v. The verifier computes
     C_d = cap*G - C_v = d*G + (-r_v)*H homomorphically, and the prover
     proves d in [0, 2^n) the same way, with bit blindings constrained so
     sum_i 2^i * C_{d,i} == C_d exactly.

Every proof is bound to a request context (predicate id, version, nonce,
cap, timestamp bucket) through the Fiat-Shamir transcript => replays under
a different context fail verification (non-repudiation + freshness).

This is a plain O(n)-size baseline; the Rust engine (dalek Bulletproofs)
provides the O(log n)-size production path. Both implement the same
gateway-facing interface.
"""
from __future__ import annotations
import secrets
from dataclasses import dataclass, field

from .curve import G, H, N, Point, multi_scalar_weighted
from .primitives import Transcript, commit, rand_scalar

DOMAIN = b"zkgw/rangeproof/bitor/v1"


@dataclass
class BitOrProof:
    a0: Point
    a1: Point
    e0: int
    z0: int
    z1: int


@dataclass
class RangeLeqProof:
    """Proof that committed v satisfies 0 <= v <= cap (n-bit values)."""
    nbits: int
    bit_commitments_v: list[Point]
    bit_proofs_v: list[BitOrProof]
    bit_commitments_d: list[Point]
    bit_proofs_d: list[BitOrProof]

    def commitment_v(self) -> Point:
        w = [1 << i for i in range(self.nbits)]
        return multi_scalar_weighted(self.bit_commitments_v, w)

    def size_bytes(self) -> int:
        pts = len(self.bit_commitments_v) + len(self.bit_commitments_d)
        for prfs in (self.bit_proofs_v, self.bit_proofs_d):
            pts += 2 * len(prfs)
        scalars = 3 * (len(self.bit_proofs_v) + len(self.bit_proofs_d))
        return pts * 33 + scalars * 32


# ------------------------------------------------------------------ helpers
def _decompose(value: int, nbits: int) -> list[int]:
    return [(value >> i) & 1 for i in range(nbits)]


def _or_prove_phase1(bit: int, C: Point, r: int):
    """Phase 1 of CDS OR-proof: produce announcements (a0, a1) and state.

    Branch 0 statement: C       = r*H     (bit == 0)
    Branch 1 statement: C - G   = r*H     (bit == 1)
    The honest branch is proved for real; the other is simulated.
    """
    if bit == 0:
        w = rand_scalar()
        a0 = w * H
        e1, z1 = rand_scalar(), rand_scalar()
        a1 = z1 * H - e1 * (C - G)
        return a0, a1, {"bit": 0, "w": w, "r": r, "e1": e1, "z1": z1}
    else:
        w = rand_scalar()
        a1 = w * H
        e0, z0 = rand_scalar(), rand_scalar()
        a0 = z0 * H - e0 * C
        return a0, a1, {"bit": 1, "w": w, "r": r, "e0": e0, "z0": z0}


def _or_prove_phase2(state: dict, e: int) -> tuple[int, int, int]:
    """Phase 2: split global challenge, answer honest branch."""
    if state["bit"] == 0:
        e1, z1 = state["e1"], state["z1"]
        e0 = (e - e1) % N
        z0 = (state["w"] + e0 * state["r"]) % N
    else:
        e0, z0 = state["e0"], state["z0"]
        e1 = (e - e0) % N
        z1 = (state["w"] + e1 * state["r"]) % N
    return e0, z0, z1


def _or_verify(C: Point, prf: BitOrProof, e: int) -> bool:
    e1 = (e - prf.e0) % N
    if prf.z0 * H != prf.a0 + prf.e0 * C:
        return False
    if prf.z1 * H != prf.a1 + e1 * (C - G):
        return False
    return True


def _bind_context(ts: Transcript, context: dict) -> None:
    for key in sorted(context):
        ts.absorb(b"ctx/" + key.encode(), str(context[key]).encode())


# ------------------------------------------------------------------ prover
def prove_range_leq(value: int, cap: int, nbits: int, context: dict) -> RangeLeqProof:
    """Produce proof that 0 <= value <= cap. Raises if the claim is false,
    so an honest prover cannot accidentally prove an out-of-policy value."""
    if not (0 <= value <= cap):
        raise ValueError("predicate violated: value outside [0, cap], refusing to prove")
    if cap >= (1 << nbits):
        raise ValueError("cap must fit in nbits")

    d = cap - value
    bits_v = _decompose(value, nbits)
    bits_d = _decompose(d, nbits)

    # --- bit commitments for v (free blindings)
    r_v_bits = [rand_scalar() for _ in range(nbits)]
    C_v_bits = [commit(b, r) for b, r in zip(bits_v, r_v_bits)]
    r_v = sum((1 << i) * r_v_bits[i] for i in range(nbits)) % N

    # --- bit commitments for d, constrained so sum 2^i C_{d,i} == cap*G - C_v
    # target blinding for d's aggregate is  -r_v  (mod N)
    r_d_target = (-r_v) % N
    r_d_bits = [rand_scalar() for _ in range(nbits)]
    r_d_bits[0] = (r_d_target - sum((1 << i) * r_d_bits[i] for i in range(1, nbits))) % N
    C_d_bits = [commit(b, r) for b, r in zip(bits_d, r_d_bits)]

    # --- Fiat-Shamir: bind context + all commitments + all announcements
    ts = Transcript(DOMAIN)
    _bind_context(ts, context)
    ts.absorb_int(b"cap", cap)
    ts.absorb_int(b"nbits", nbits)
    for C in C_v_bits:
        ts.absorb_point(b"Cv", C)
    for C in C_d_bits:
        ts.absorb_point(b"Cd", C)

    states_v, ann_v = [], []
    for b, C, r in zip(bits_v, C_v_bits, r_v_bits):
        a0, a1, st = _or_prove_phase1(b, C, r)
        states_v.append(st)
        ann_v.append((a0, a1))
        ts.absorb_point(b"a0v", a0)
        ts.absorb_point(b"a1v", a1)
    states_d, ann_d = [], []
    for b, C, r in zip(bits_d, C_d_bits, r_d_bits):
        a0, a1, st = _or_prove_phase1(b, C, r)
        states_d.append(st)
        ann_d.append((a0, a1))
        ts.absorb_point(b"a0d", a0)
        ts.absorb_point(b"a1d", a1)

    e = ts.challenge(b"e")

    prfs_v = []
    for st, (a0, a1) in zip(states_v, ann_v):
        e0, z0, z1 = _or_prove_phase2(st, e)
        prfs_v.append(BitOrProof(a0, a1, e0, z0, z1))
    prfs_d = []
    for st, (a0, a1) in zip(states_d, ann_d):
        e0, z0, z1 = _or_prove_phase2(st, e)
        prfs_d.append(BitOrProof(a0, a1, e0, z0, z1))

    return RangeLeqProof(nbits, C_v_bits, prfs_v, C_d_bits, prfs_d)


# ------------------------------------------------------------------ verifier
def verify_range_leq(proof: RangeLeqProof, cap: int, context: dict) -> bool:
    n = proof.nbits
    if cap >= (1 << n):
        return False
    if not (len(proof.bit_commitments_v) == len(proof.bit_proofs_v) == n):
        return False
    if not (len(proof.bit_commitments_d) == len(proof.bit_proofs_d) == n):
        return False

    # Recompute Fiat-Shamir challenge over the same transcript
    ts = Transcript(DOMAIN)
    _bind_context(ts, context)
    ts.absorb_int(b"cap", cap)
    ts.absorb_int(b"nbits", n)
    for C in proof.bit_commitments_v:
        ts.absorb_point(b"Cv", C)
    for C in proof.bit_commitments_d:
        ts.absorb_point(b"Cd", C)
    for prf in proof.bit_proofs_v:
        ts.absorb_point(b"a0v", prf.a0)
        ts.absorb_point(b"a1v", prf.a1)
    for prf in proof.bit_proofs_d:
        ts.absorb_point(b"a0d", prf.a0)
        ts.absorb_point(b"a1d", prf.a1)
    e = ts.challenge(b"e")

    # 1. every bit commitment holds 0 or 1
    for C, prf in zip(proof.bit_commitments_v, proof.bit_proofs_v):
        if not _or_verify(C, prf, e):
            return False
    for C, prf in zip(proof.bit_commitments_d, proof.bit_proofs_d):
        if not _or_verify(C, prf, e):
            return False

    # 2. homomorphic consistency:  sum 2^i C_{d,i}  ==  cap*G - sum 2^i C_{v,i}
    w = [1 << i for i in range(n)]
    C_v = multi_scalar_weighted(proof.bit_commitments_v, w)
    C_d = multi_scalar_weighted(proof.bit_commitments_d, w)
    return C_d == cap * G - C_v
