# ZK Proof Gateway, Implementation Architecture & High-Level Design

Reference prototype for *"Zero-Knowledge Data Minimization for Multi-Agent AI Systems"* (IEEE Access draft). This HLD maps 1:1 to paper Section IV (architecture), Section V (case study), and Section VI (feasibility); measured results are in `results/RESULTS.md`.

---

## 1. System overview

**Design goal:** when agent A must establish that agent B's private data satisfies a policy, the wire carries a *predicate proof*, never the data and never a natural-language claim.

```
                       ┌──────────────────────────────┐
                       │   GOVERNANCE / RISK TEAM     │
                       │  (holds registry signing key)│
                       └──────────────┬───────────────┘
                                      │ publishes signed predicates
                                      ▼
┌──────────────┐   1.request   ┌──────────────────┐    ┌───────────────────┐
│  RISK AGENT   │─────────────▶│  PROOF GATEWAY   │───▶│ AUDIT LOG          │
│  (verifier/   │◀─────────────│  - registry      │    │ (append-only,      │
│   relying)    │  6.ALLOW/DENY│  - verifier      │    │  hash-chained)     │
└──────────────┘   +audit hash │  - context/nonce │    └───────────────────┘
                               └───────┬──────────┘
                       2.challenge ctx │ ▲ 5.envelope{commitment, proof}
                                       ▼ │
                              ┌────────────────────┐
                              │  EXECUTION AGENT   │   3.fetch   ┌────────────┐
                              │  prover sidecar    │◀───────────│ SOURCE OF   │
                              │  (ZK engine)       │  4.commit+  │ TRUTH (OMS/ │
                              │  PRIVATE: notional │    prove    │ positions)  │
                              └────────────────────┘             └────────────┘
```

Mermaid component view:

```mermaid
flowchart LR
    GOV[Governance team] -->|signs & publishes| REG[(Predicate Registry)]
    RA[Risk Agent - verifier] -->|1 request predicate check| GW[Proof Gateway]
    GW -->|2 context: nonce, predicate id@v| EA[Execution Agent + Prover sidecar]
    EA -->|3 fetch private value| SRC[(Source of truth - OMS/positions)]
    EA -->|4 envelope: commitment + ZK proof| GW
    GW -->|verify against REG| REG
    GW -->|append entry| AUD[(Hash-chained Audit Log)]
    GW -->|5 ALLOW/DENY + audit hash| RA
```

## 2. Components (and where they live in this repo)

| Component | Responsibility | Code |
|---|---|---|
| **Predicate Registry** | Governance-owned catalog of predicate definitions (`range_leq`, params, bit-width, unit), each Schnorr-signed by the governance key. Agents cannot publish; gateway re-verifies signatures on read (defends registry-tamper). | `python/zkgw/gateway.py::PredicateRegistry` |
| **Proof Gateway** | Issues request contexts (fresh nonce, predicate id@version, requester/prover ids, timestamp); verifies envelopes against registry predicates; appends audit entries. Stateless between requests except the audit chain head. | `gateway.py::ProofGateway` |
| **Prover sidecar** | Runs next to the data-holding agent (or the source system, §6). Two interchangeable engines behind one interface: **(E1)** pure-Python Pedersen bit-decomposition with CDS OR-Sigma proofs, Fiat-Shamir (O(n) size, auditable ~300 LoC); **(E2)** Rust dalek **Bulletproofs** (O(log n) size, production path). | `zkgw/rangeproof.py`, `rust/zkrp/` |
| **Proof envelope** | The proposed protocol extension: a `zk-attach/v0` JSON object carried with a tool call / handoff. Contains predicate id@version, engine id, request context, base64 proof. **The private value appears nowhere.** | `gateway.py::make_envelope` |
| **Audit log** | Append-only JSONL, `entry_hash = SHA256(prev_hash || canonical(entry))`. Stores commitment + proof hash + result -> non-repudiable, replayable verification record without storing data. | `gateway.py::AuditLog` |
| **Agents** | `ExecutionAgent` (private `notional_cents`, never exported), `RiskAgent` (relying party; sees only decision + envelope). | `gateway.py` |

## 3. Cryptographic design

**Statement (predicate `range_leq`):** PoK{(v, r) : C_v = v*G + r*H ∧ 0 <= v <= cap}.

Engine E1 construction (fully implemented, `rangeproof.py`):
1. Bit-commit v: `C_i = b_i*G + r_i*H`; the value commitment is defined as `C_v = sum 2^i*C_i` (verifier recomputes, no separate linking proof needed).
2. Each bit proved in {0,1} with a Cramer-Damgard-Schoenmakers OR-composition of two Schnorr proofs (branch 0: `C = r*H`; branch 1: `C - G = r*H`), one **global Fiat-Shamir challenge** split per-bit as `e = e0 + e1`.
3. `v <= cap` via the homomorphic difference: verifier computes `C_d = cap*G - C_v` itself; prover range-proves `d = cap - v` with bit blindings constrained so `sum 2^i*C_{d,i} = C_d` **exactly** (blinding of bit 0 solves the linear constraint).
4. **Context binding:** the Fiat-Shamir transcript absorbs `{request_id, nonce, predicate_id, predicate_version, requester, prover, ts}` before any commitment -> a proof is valid only for the exact request that solicited it (replay/splice across nonces, agents, or predicate versions fails, verified in tests T3/T4).

Engine E2 (Rust) proves `v in [0, 2^n)` with Bulletproofs over ristretto255; `v <= cap` uses the identical two-statement reduction (or one 2-aggregate proof). Context binding via Merlin transcript `append_message("context", ...)`, verified by the cross-context negative test.

**Trust assumptions:** discrete log on secp256k1 / ristretto255; random-oracle model for Fiat-Shamir; `H` derived by hash-to-curve (no known dlog relation to `G`); governance signing key secure; verifier (gateway) honest, the prover is *not* trusted.

## 4. Protocol flow (Section V sequence diagram)

```mermaid
sequenceDiagram
    participant RA as Risk Agent
    participant GW as Proof Gateway
    participant EA as Execution Agent (prover)
    participant SRC as Source of truth
    participant AUD as Audit log
    RA->>GW: check(pretrade_notional_cap@v1, prover=EA)
    GW->>GW: load predicate, verify governance signature
    GW->>EA: context {nonce, request_id, predicate id@v, ids, ts}
    EA->>SRC: fetch notional (stays inside trust cell)
    EA->>EA: commit C_v, prove v ≤ cap bound to context
    EA-->>GW: envelope {zk-attach/v0, C_v, proof}
    GW->>GW: verify (registry cap, context transcript)
    GW->>AUD: append {commitment, proof hash, PASS, ids} -> entry_hash
    GW-->>RA: ALLOW + audit entry hash
    Note over RA: never sees notional, only predicate truth
```

## 5. Proposed protocol extension (`zk-attach/v0`)

No current agent protocol carries a proof slot; this prototype defines one that fits MCP `tools/call` params or an A2A message part without breaking existing schemas. Both bindings are implemented (`agent_server.py` and `go/gatewayservice` each speak both surfaces on the same HTTP endpoint, sharing one verification chain and one audit/orders ledger underneath):

```json
{
  "method": "tools/call",
  "params": {
    "name": "submit_order",
    "arguments": { "order_ref": "ord-9912" },
    "zk_attachment": {
      "schema": "zk-attach/v0",
      "predicate_id": "pretrade_notional_cap",
      "predicate_version": 1,
      "engine": "bulletproofs-ristretto255 | bitor-sigma-secp256k1-py",
      "context": { "request_id": "...", "nonce": "...", "requester": "...", "prover": "...", "ts": 0 },
      "proof_b64": "..."
    }
  }
}
```

The A2A binding carries the identical attachment inside a `Message`'s data part instead of `tools/call` params -- A2A has no native "tool call" concept, so the governed action's name and arguments travel alongside the attachment in the same data part, and the response is a `Task` rather than a JSON-RPC result:

```json
{
  "method": "message/send",
  "params": {
    "message": {
      "role": "user", "kind": "message", "messageId": "m-1",
      "parts": [{
        "kind": "data",
        "data": {
          "skill": "submit_order",
          "arguments": { "order_ref": "ord-9912" },
          "zk_attachment": { "schema": "zk-attach/v0", "...": "..." }
        }
      }]
    }
  }
}
```

Discovery differs too: MCP callers learn the governed predicate from `tools/list`'s `x_zk_required` field; A2A callers learn it from the Agent Card served at `GET /.well-known/agent.json`, in the `submit_order` skill's description. Both callers obtain a request context from the same `zk/context` method before proving, regardless of which surface they then call back on.

Semantics: a gateway/middleware verifying the attachment MAY authorize the call without the sensitive argument ever being present; absence of a required attachment for a registered predicate => deny-by-default.

## 6. Deployment topologies & the source-integrity question

A ZK proof binds the statement to the **committed** value, it cannot, by itself, show the committed value equals the system-of-record value. Two topologies address this (paper Section IV/VII):

- **(A) Source-side prover (recommended):** the prover sidecar is co-located with the source of truth (OMS/position service), which signs `C_v`. The agent merely transports the envelope. Compromise of the LLM agent cannot alter what is proved.
- **(B) Agent-side prover + data attestation:** the source returns `(value, signature over commitment opening)`; the agent proves over the attested commitment. Weaker (agent sees the value) but requires no source-side changes; still removes the value from **inter-agent** traffic, which is this paper's scope.

## 7. Multi-hop composition patterns

- **(a) Chained per-hop proofs:** each hop verifies + re-requests; latency adds per hop (measured: +~1.2-2.1 ms verify per hop with E2), max granularity in the audit chain.
- **(b) Aggregated proof at trust boundary:** m range statements in one Bulletproofs aggregate; measured m=16 -> **928 B and 17.4 ms verify vs 10,752 B and ~33.5 ms** for 16 singles (charts in `results/aggregation.png`). Coarser audit granularity, one boundary check. Prover-side aggregation cost grows ~linearly (219 ms at m=16 on this vCPU) -> pre-compute/async.

## 8. Latency budget (measured, single 2.8 GHz Xeon vCPU)

| Pipeline location | Budget | E2 Bulletproofs (32-bit) | Verdict |
|---|---|---|---|
| Real-time tool-call loop (per call) | ~10-50 ms | prove 8.1 ms + verify 1.2 ms | fits; prove can be async/pre-staged |
| Agent handoff / delegation | ~100 ms-1 s | 2x(prove+verify) <= 20 ms | comfortably fits |
| Batch/settlement, audit re-check | seconds+ | verify-only replay 1-2 ms/entry | trivial |
| Same, engine E1 (Python baseline) |, | 749 ms prove / 766 ms verify | reference baseline only |

## 9. Repo map & how to run

```
python/zkgw/{curve,primitives,rangeproof,gateway}.py   # library
python/demo_trading.py      # Section V end-to-end case study
python/tests_soundness.py   # T0-T7 adversarial suite (11 checks)
python/bench.py             # benchmark harness + charts
rust/zkrp/                  # Bulletproofs engine (prove|verify|bench CLI)
results/                    # measured outputs: CSV/JSON/PNG/transcripts
```

Run: `python3 demo_trading.py`, `python3 tests_soundness.py`, `python3 bench.py`; Rust: `cargo build --release && ./target/release/zkrp bench`.

## 10. Known prototype limitations (feed paper Section VII)

- E1 is not constant-time; secp256k1 in pure Python is for auditability, not production. E2 (dalek) is the production path.
- Only `range_leq` is wired end-to-end; set-membership and boolean composition are registry `ptype`s left as stubs by design.
- Gateway is in-process; a networked deployment adds transport auth (mTLS/SPIFFE), orthogonal to the proof layer.
- Metadata leakage (which predicate, when, how often) is *not* hidden, matches paper §VII.
- Proof-of-consistency with the source of truth requires topology A or B above; the ZKP alone does not provide it.
