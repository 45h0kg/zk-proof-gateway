"""ZK Proof Gateway: registry, audit log, proof envelope, gateway service, agents.

Maps to paper Section IV (Proposed Architecture):
  PredicateRegistry  - governance-owned, signed predicate definitions
                       (agents CANNOT define their own predicates)
  AuditLog           - append-only, hash-chained verification records
  ProofEnvelope      - proposed MCP/A2A schema extension: a proof attachment
                       travelling WITH a tool call / handoff instead of data
  ProofGateway       - verifies proofs against registry predicates, logs
  ExecutionAgent     - holds PRIVATE trading state; produces proofs on request
  RiskAgent          - consumes verified predicate results, never raw data
"""
from __future__ import annotations
import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, asdict, field

from .curve import Point
from .primitives import sign, sig_verify, rand_scalar
from . import rangeproof
from .rangeproof import RangeLeqProof, BitOrProof


# ------------------------------------------------------------------ registry
@dataclass
class Predicate:
    predicate_id: str
    version: int
    ptype: str                 # "range_leq"
    params: dict               # {"cap": int, "nbits": int, "unit": "USD_cents"}
    owner: str                 # governance team id
    signature: tuple[int, int] | None = None

    def canonical_bytes(self) -> bytes:
        body = {k: v for k, v in asdict(self).items() if k != "signature"}
        return json.dumps(body, sort_keys=True).encode()


class PredicateRegistry:
    """Governance-owned. Predicates are Schnorr-signed by the governance key;
    the gateway refuses unsigned/tampered predicates. This is what prevents a
    compromised agent from registering its own loose check."""

    def __init__(self, governance_pub: Point):
        self._store: dict[tuple[str, int], Predicate] = {}
        self._gov_pub = governance_pub

    def publish(self, pred: Predicate) -> None:
        if pred.signature is None or not sig_verify(
            self._gov_pub, pred.canonical_bytes(), pred.signature
        ):
            raise PermissionError("registry: predicate not signed by governance key")
        self._store[(pred.predicate_id, pred.version)] = pred

    def get(self, predicate_id: str, version: int) -> Predicate:
        pred = self._store[(predicate_id, version)]
        if not sig_verify(self._gov_pub, pred.canonical_bytes(), pred.signature):
            raise PermissionError("registry: stored predicate failed signature check")
        return pred


# ------------------------------------------------------------------ audit log
class AuditLog:
    """Append-only hash chain: entry_hash = H(prev_hash || canonical(entry))."""

    def __init__(self, path: str):
        self.path = path
        self._prev = "0" * 64
        open(path, "w").close()

    def append(self, record: dict) -> str:
        record = dict(record, prev_hash=self._prev)
        body = json.dumps(record, sort_keys=True)
        entry_hash = hashlib.sha256((self._prev + body).encode()).hexdigest()
        record["entry_hash"] = entry_hash
        with open(self.path, "a") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")
        self._prev = entry_hash
        return entry_hash

    @staticmethod
    def verify_chain(path: str) -> bool:
        prev = "0" * 64
        with open(path) as f:
            for line in f:
                rec = json.loads(line)
                claimed = rec.pop("entry_hash")
                if rec.get("prev_hash") != prev:
                    return False
                body = json.dumps(rec, sort_keys=True)
                if hashlib.sha256((prev + body).encode()).hexdigest() != claimed:
                    return False
                prev = claimed
        return True


# ------------------------------------------------------------------ envelope
def _ser_point(pt: Point) -> str:
    return pt.compress().hex()


def _de_point(hx: str) -> Point:
    raw = bytes.fromhex(hx)
    if raw == b"\x00" * 33:
        from .curve import IDENTITY
        return IDENTITY
    x = int.from_bytes(raw[1:], "big")
    from .curve import P, B
    y2 = (pow(x, 3, P) + B) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        raise ValueError("invalid point")
    if (y & 1) != (raw[0] & 1):
        y = P - y
    return Point(x, y)


def serialize_proof(proof: RangeLeqProof) -> bytes:
    def ser_bits(prfs):
        return [
            {"a0": _ser_point(p.a0), "a1": _ser_point(p.a1),
             "e0": hex(p.e0), "z0": hex(p.z0), "z1": hex(p.z1)}
            for p in prfs
        ]
    obj = {
        "nbits": proof.nbits,
        "Cv": [_ser_point(c) for c in proof.bit_commitments_v],
        "Pv": ser_bits(proof.bit_proofs_v),
        "Cd": [_ser_point(c) for c in proof.bit_commitments_d],
        "Pd": ser_bits(proof.bit_proofs_d),
    }
    return json.dumps(obj, separators=(",", ":")).encode()


def deserialize_proof(raw: bytes) -> RangeLeqProof:
    obj = json.loads(raw)
    def de_bits(items):
        return [
            BitOrProof(_de_point(d["a0"]), _de_point(d["a1"]),
                       int(d["e0"], 16), int(d["z0"], 16), int(d["z1"], 16))
            for d in items
        ]
    return RangeLeqProof(
        obj["nbits"],
        [_de_point(c) for c in obj["Cv"]], de_bits(obj["Pv"]),
        [_de_point(c) for c in obj["Cd"]], de_bits(obj["Pd"]),
    )


def make_envelope(predicate: Predicate, proof_bytes: bytes, engine: str,
                  context: dict) -> dict:
    """Proposed `zk_attachment` slot for an MCP tools/call or A2A message part.

    The important property: the envelope carries a commitment and a proof;
    the underlying value appears nowhere in it.
    """
    return {
        "schema": "zk-attach/v0",
        "predicate_id": predicate.predicate_id,
        "predicate_version": predicate.version,
        "engine": engine,
        "context": context,               # nonce, ts bucket, requester
        "proof_b64": base64.b64encode(proof_bytes).decode(),
    }


# ------------------------------------------------------------------ gateway
class ProofGateway:
    def __init__(self, registry: PredicateRegistry, audit: AuditLog):
        self.registry = registry
        self.audit = audit

    def new_request_context(self, predicate_id: str, version: int,
                            requester: str, prover: str,
                            action_ref: str = "") -> dict:
        return {
            "request_id": secrets.token_hex(8),
            "nonce": secrets.token_hex(16),
            "action_ref": action_ref,
            "predicate_id": predicate_id,
            "predicate_version": version,
            "requester": requester,
            "prover": prover,
            "ts": int(time.time()),
        }

    def verify(self, envelope: dict) -> dict:
        t0 = time.perf_counter()
        pred = self.registry.get(envelope["predicate_id"], envelope["predicate_version"])
        proof = deserialize_proof(base64.b64decode(envelope["proof_b64"]))
        ok = False
        if pred.ptype == "range_leq":
            ok = rangeproof.verify_range_leq(
                proof, pred.params["cap"], envelope["context"]
            )
        verify_ms = (time.perf_counter() - t0) * 1000
        entry = {
            "ts": int(time.time()),
            "request_id": envelope["context"]["request_id"],
            "predicate": f'{pred.predicate_id}@v{pred.version}',
            "requester": envelope["context"]["requester"],
            "prover": envelope["context"]["prover"],
            "engine": envelope["engine"],
            "commitment_Cv": _ser_point(proof.commitment_v()),
            "proof_sha256": hashlib.sha256(
                base64.b64decode(envelope["proof_b64"])).hexdigest(),
            "result": "PASS" if ok else "FAIL",
            "verify_ms": round(verify_ms, 3),
        }
        entry_hash = self.audit.append(entry)
        return {"ok": ok, "audit_entry": entry_hash, "verify_ms": verify_ms}


# ------------------------------------------------------------------ agents
class ExecutionAgent:
    """Trading execution agent. `notional_cents` is PRIVATE state that never
    leaves this object; only commitments and proofs do."""

    def __init__(self, agent_id: str, notional_cents: int):
        self.agent_id = agent_id
        self._notional_cents = notional_cents   # private

    def prove(self, predicate: Predicate, context: dict) -> dict:
        if predicate.ptype != "range_leq":
            raise ValueError("unsupported predicate type")
        t0 = time.perf_counter()
        proof = rangeproof.prove_range_leq(
            self._notional_cents, predicate.params["cap"],
            predicate.params["nbits"], context,
        )
        prove_ms = (time.perf_counter() - t0) * 1000
        env = make_envelope(predicate, serialize_proof(proof),
                            "bitor-sigma-secp256k1-py", context)
        env["_prove_ms"] = round(prove_ms, 3)   # metrics only, not protocol
        return env


class RiskAgent:
    """Pre-trade risk agent. Requests compliance evidence via the gateway.
    Sees: predicate result + commitment + audit hash. Never sees notional."""

    def __init__(self, agent_id: str, gateway: ProofGateway):
        self.agent_id = agent_id
        self.gateway = gateway

    def check_pretrade(self, exec_agent: ExecutionAgent,
                       predicate_id: str, version: int,
                       action_ref: str = "") -> dict:
        pred = self.gateway.registry.get(predicate_id, version)
        ctx = self.gateway.new_request_context(
            predicate_id, version, self.agent_id, exec_agent.agent_id,
            action_ref=action_ref)
        envelope = exec_agent.prove(pred, ctx)
        result = self.gateway.verify(envelope)
        return {"decision": "ALLOW" if result["ok"] else "DENY",
                "envelope": envelope, **result}
