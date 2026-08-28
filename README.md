# ZK Proof Gateway

[![CI](https://github.com/45h0kg/zk-proof-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/45h0kg/zk-proof-gateway/actions/workflows/ci.yml)

Reference implementation for the paper *"Zero-Knowledge Data Minimization
for Multi-Agent AI Systems: A Proof-Verification Gateway Architecture for
Data Privacy Between Agents"* (arXiv link: TBD).

The problem: when one AI agent must convince another that a value complies
with policy, today it either sends the raw value or asserts compliance in
natural language. The first over-shares; the second is exactly what prompt
injection attacks. This prototype demonstrates a third option: the agent
sends a zero-knowledge proof of a governance-defined predicate (here,
"order notional <= pre-trade cap"), so the relying agent learns the policy
fact and nothing else. The sensitive value never crosses the agent
boundary, and the decision is bound to a specific request, action, and
policy version, then recorded in a hash-chained audit log.

## Repository layout

```
python/zkgw/            core library
  curve.py              secp256k1 group operations (educational, not constant-time)
  primitives.py         Fiat-Shamir transcript, Pedersen commitments, Schnorr
  rangeproof.py         ZK range/threshold proofs (Sigma bit-OR engine, "E1")
  gateway.py            predicate registry, proof gateway, audit log, agents
python/governance_cli.py  keygen / sign / verify predicates (governing entity tool)
python/demo_trading.py    end-to-end case study from the paper (Section V)
python/prover_service.py  prover as an HTTP service, Python E1 engine
python/tests_soundness.py adversarial suite T0-T7 (11 checks)
python/bench.py           benchmark harness, writes results/ CSVs and charts
rust/zkrp/                Bulletproofs engine ("E2", dalek ristretto255) CLI
go/gatewayservice/        gateway rewrite in Go, verifies via rust/zkrp (E2)
go/proverservice/         prover rewrite in Go, proves via rust/zkrp (E2)
docker/                   Dockerfiles + compose for the Go+Rust stack
helm/zk-proof-gateway/    Helm chart for the Go+Rust stack (lint/template-verified)
terraform/gke/, eks/      reference cluster + helm_release modules (unapplied)
experiments/run_all.sh    one-command full reproduction with logged output
results/                  sample outputs from a logged run (regenerate with run_all.sh)
HLD.md                    design document with diagrams
IMPLEMENTATION_HLD.md      architecture for the containerization/Go+Rust build-out
IMPLEMENTATION_LLD.md      file-by-file detail for the same
CHANGELOG.md               PR-by-PR record of the containerization/hardening effort
```

## Requirements

- Python 3.10+ (standard library only; `matplotlib` and `numpy` needed for
  `bench.py` charts)
- Rust 1.75+ with cargo (for the Bulletproofs engine)
- Linux or macOS

## Quick start

```bash
cd python
python3 demo_trading.py      # end-to-end pre-trade check; prints the wire envelope
python3 tests_soundness.py   # adversarial suite; expect "11/11 checks passed"
python3 bench.py             # microbenchmarks + charts into ../results/
cd ../rust/zkrp
cargo build --release
./target/release/zkrp bench  # Bulletproofs numbers as JSON
```

Or run everything, including the governance workflow, with one command:

```bash
bash experiments/run_all.sh   # writes results/execution_log.txt + artifacts
```

## Agentic protocol demo (zk-attach/v0 over JSON-RPC: MCP and A2A)

`agent_server.py` (and its Go rewrite, `go/gatewayservice`) is an
execution-venue agent speaking **two** protocol surfaces on the same HTTP
endpoint, sharing one verification chain, one audit log, and one orders
ledger underneath:

- **MCP-shaped**: advertises a governed `submit_order` tool whose
  `x_zk_required` field names the predicate a caller must prove, and
  enforces the middleware rule on `tools/call` -- a governed call without a
  valid `zk_attachment` is denied by default and never reaches the tool.
- **A2A (Agent2Agent)**: advertises the same governed action as a
  `submit_order` skill in an Agent Card at `GET /.well-known/agent.json`;
  the governed path is `message/send`, with a `zk_attachment` carried in a
  Message data part instead of `tools/call` params (see `HLD.md` section 5
  for the exact shape). `tasks/get` polls a task by id; `tasks/cancel`
  always errors, since every task here completes synchronously during
  `message/send`.

Both surfaces share `zk/context` for issuing request contexts -- a caller
obtains a context the same way regardless of which surface it then calls
back on.

`verify_e2e.py` boots the server and plays an execution agent holding a
private notional, then checks five MCP scenarios plus the A2A surface over
the wire, and the audit chain:

```bash
cd python
python3 verify_e2e.py     # expect "AGENTIC PROTOCOL E2E: 19/19 checks passed"
```

The five MCP scenarios are: a compliant order with a valid proof (ALLOW,
notional absent from every wire byte); a governed call with no attachment
(denied by default); a tampered proof (denied, recorded as an audited
FAIL); a valid attachment replayed against a different order (denied by
single-use context binding); and an over-cap notional (the honest prover
refuses locally, so nothing is ever sent). The A2A checks confirm the
Agent Card, `message/send`'s ALLOW/deny-by-default paths, `tasks/get`,
`tasks/cancel`, and that an order placed via A2A lands on the same ledger
`venue/orders` (MCP) reports.

## Prover as a separate service

The prover can run as a real, separate process instead of in-process with
the gateway -- this is what closes the gap between the demo above and the
paper's described topology (prover co-located with the source of truth,
gateway elsewhere). Two implementations exist behind the same HTTP contract
(`POST /prove`, `GET /healthz`):

- `python/prover_service.py` -- the Python Sigma-OR engine (E1), stdlib-only.
- `go/proverservice` + `go/gatewayservice` -- a Go rewrite of both prover and
  gateway, verifying proofs via the Rust Bulletproofs engine (`rust/zkrp`,
  E2) invoked as a subprocess. Predicate registries signed by
  `governance_cli.py` verify unmodified against the Go gateway -- the
  governance signature scheme (Schnorr over secp256k1) is replicated exactly.
  Verification drops from ~500ms (E1) to single-digit milliseconds (E2).

`verify_e2e.py` drives either combination via two environment variables:
`ZKGW_PROVER_URL` points it at an already-running prover service instead of
proving in-process, and `ZKGW_GATEWAY_CMD` swaps which gateway binary it
spawns (default: the in-repo Python `agent_server.py`). For example, against
the Go+Rust stack:

```bash
cd go
go build -o /tmp/gateway-service ./gatewayservice
go build -o /tmp/prover-service ./proverservice
ZKGW_SOURCE_VALUE=735000000 /tmp/prover-service --port 8753 \
  --zkrp-bin ../rust/zkrp/target/release/zkrp &
cd ../python
ZKGW_PROVER_URL=http://127.0.0.1:8753 \
ZKGW_GATEWAY_CMD="/tmp/gateway-service --zkrp-bin ../rust/zkrp/target/release/zkrp" \
  python3 verify_e2e.py     # expect "AGENTIC PROTOCOL E2E: 19/19 checks passed"
```

## Run with Docker

`docker/docker-compose.yml` containerizes the Go+Rust gateway and prover
with the prover on an internal-only network (never published to the host) --
see [`docker/README.md`](docker/README.md) for the exact, verified commands
to bring the stack up and run the five-scenario verifier against it.

## Kubernetes (Helm)

`helm/zk-proof-gateway/` deploys the same Go+Rust gateway and prover:
prover co-located in one pod with a placeholder source-of-truth container
(the paper's topology A), gateway as a separate ClusterIP-only Deployment,
and two NetworkPolicies: `networkpolicy.yaml` denies **all** ingress to the
prover pod (see that file for why it's deny-*all*, not "allow from the
gateway" -- the gateway never calls the prover directly in this protocol),
and `gateway-networkpolicy.yaml` restricts ingress to the gateway pod to
its own namespace (defense-in-depth; the gateway does need to be
reachable, unlike the prover).

The audit log is a `PersistentVolumeClaim`, not an `emptyDir` -- confirmed
by deleting the gateway pod under load and checking the (pre-restart)
entries were still there and the hash chain still verified afterward. An
`emptyDir` would silently lose the entire non-repudiation trail on every
pod restart/reschedule.

Build and push `zkgw-gateway`/`zkgw-prover` images (from `docker/Dockerfile.gateway`
/ `docker/Dockerfile.prover`) to a registry your cluster can pull from, set
`gateway.image`/`prover.image` in `values.yaml` accordingly, then:

```bash
helm lint helm/zk-proof-gateway              # verified: passes
helm template zkgw helm/zk-proof-gateway     # verified: renders, includes both NetworkPolicies + the PVC
helm install zkgw helm/zk-proof-gateway      # verified: see below
```

**`helm install` has actually been run and verified**, against a local
`kind` cluster: images built and `kind load docker-image`d in, chart
installed with a real governance-signed predicate, PVC bound, both pods
healthy. The five-scenario verifier was run as an in-cluster pod (mounting
the same audit PVC, reaching the gateway via its Service DNS name and the
prover via its pod IP) and passed 12/12, at ~2.5ms verify latency even
inside the kind VM. `kindnet` (kind's default CNI) turned out to genuinely
enforce both NetworkPolicies -- confirmed by watching the prover connection
time out with the policy on and succeed with it temporarily disabled, not
assumed.

This test run also caught two real bugs, both fixed:
- `values.yaml`'s `prover.sourceValue` was a bare YAML integer; Helm's
  YAML->JSON->`interface{}` pipeline decodes all numbers as `float64`,
  which rendered `735000000` as `7.35e+08` in the template and broke the
  prover's `strconv.ParseInt`. Now a quoted string.
- `go/internal/auditlog.New()` (and the Python `AuditLog.__init__` it was
  ported from) unconditionally truncated the audit file on every process
  start -- harmless for a one-shot local script, but it meant the PVC above
  bought nothing: a gateway pod restart still silently wiped the whole
  trail. Both now resume the hash chain from the last entry instead of
  truncating; verified by deleting the gateway pod mid-test and confirming
  prior entries survived and the chain still verified across the restart
  boundary.

## Terraform (reference modules, unapplied)

`terraform/gke/` and `terraform/eks/` are minimal reference modules that
stand up a small cluster and `helm_release` the chart above. Both have been
`terraform validate`d and `terraform fmt -check`ed against real provider
schemas (no cloud credentials needed for that); **neither has been
`apply`d against a real account** -- review cost, IAM scope, and the
chart's `values.yaml` before doing so yourself. Deliberately does not
attempt Confidential Space or Nitro Enclaves in this pass -- that is the
follow-up paper's work, and a half-done enclave integration is worse than
none.

## Integrating this into an agentic design

This section is the practical guide: how to take the prototype from a demo
into a real multi-agent system. The core idea is small. Anywhere one agent
today sends another a sensitive value so the receiver can check a rule,
you instead (1) register the rule as a signed predicate, (2) have the data
holder produce a proof, and (3) attach the proof to the call so the
receiver verifies policy without ever seeing the value.

### The mental model: three roles

Every integration maps your system onto three roles. They can be three
separate services or three functions in one process; what matters is the
trust boundary between them.

- **The prover** is whatever holds the sensitive data (a database, an
  order-management system, a user-profile service). It never ships the
  value; it ships a commitment and a proof. In code this is
  `ExecutionAgent.prove()` in `zkgw/gateway.py`, which wraps
  `rangeproof.prove_range_leq()`. In production you replace
  `ExecutionAgent` with a thin adapter that reads the real value from your
  source of truth and calls the same prove function.
- **The verifier** is the relying party that needs the policy answer. It
  never receives the value; it receives ALLOW/DENY plus an audit handle.
  In the demo this is the execution-venue server in `agent_server.py`,
  which calls `ProofGateway.verify()`.
- **The governing entity** is the team that owns policy. It signs
  predicates with `governance_cli.py` and distributes the public key to
  verifiers out of band. Agents are never in this role.

### Where the proof rides: the tool-call slot

The integration point in an agent framework is the tool call itself. A
governed tool declares which predicate a caller must prove, and the proof
travels as an attachment on the call. `agent_server.py` shows the exact
shape over MCP-style JSON-RPC:

1. The tool advertises its requirement in `tools/list` via an
   `x_zk_required` field naming the predicate id and version.
2. Before calling, the agent asks the verifier for a fresh single-use
   context (`zk/context`) carrying a nonce and the action reference (the
   order id, the request id, whatever uniquely names this action).
3. The prover generates a proof bound to that context.
4. The agent calls the tool with a `zk_attachment` object alongside the
   normal arguments:

   ```json
   "zk_attachment": {
     "schema": "zk-attach/v0",
     "predicate_id": "pretrade_notional_cap",
     "predicate_version": 1,
     "engine": "bulletproofs-ristretto255",
     "context": {"request_id": "...", "nonce": "...",
                 "requester": "...", "prover": "...",
                 "action_ref": "ord-9912", "ts": 0},
     "proof_b64": "..."
   }
   ```

5. The verifier's middleware enforces **deny-by-default**: a call to a
   governed tool with no valid attachment is rejected before the tool
   runs. This is the single most important rule to get right; see the
   enforcement checklist below.

If you use MCP, this maps onto `tools/call` params. If you use A2A, it maps
onto a message part. If you use a bespoke function-calling layer, add one
optional field to your tool schema. The attachment is backward compatible:
tools that are not governed simply ignore it.

### Adapting the prototype to your stack, step by step

1. **Enumerate the sensitive values agents currently pass to each other.**
   For each, ask: does the receiver need the value, or only a yes/no
   answer about it? Every yes/no is a candidate predicate.
2. **Express each as a predicate.** The prototype ships `range_leq`
   (`value <= cap`). See the patterns below for turning thresholds, floors,
   band membership, and set membership into range predicates.
3. **Register and sign them** with `governance_cli.py` (see the governing
   entity section). Version every predicate; policy changes are new
   versions, and version binding makes proofs against stale versions fail
   closed.
4. **Wrap your source of truth as a prover.** Replace `ExecutionAgent`'s
   hardcoded `notional_cents` with a function that reads the real value.
   Keep the prover co-located with the data (same pod, same process, same
   trust cell) so the orchestrating LLM agent never holds the value.
5. **Put the gateway in front of governed tools.** Wrap each governed tool
   handler so it calls `ProofGateway.verify()` on the attachment first and
   runs the tool only on ALLOW. `agent_server.py` is a complete worked
   example you can copy.
6. **Point audit at durable storage.** The prototype's `AuditLog` writes a
   local hash-chained JSONL file. In production, append to a shared,
   append-only store and shard the chain per predicate domain so unrelated
   flows do not serialize on one chain head.
7. **Choose the engine.** The Python Sigma engine (E1) is readable and
   dependency-light but slow; use it to understand the system. The Rust
   Bulletproofs engine (E2, `rust/zkrp/`) is the practical path at
   ~1 ms verification. Both sit behind the same interface.

### Predicate patterns (beyond the shipped range_leq)

Most real policies reduce to the range machinery already in the prototype:

- **Threshold / cap** (`value <= cap`): shipped directly as `range_leq`.
  Example: order notional under a pre-trade limit.
- **Floor** (`value >= floor`): prove `(value - floor)` is a non-negative
  n-bit number, i.e. run the same range construction on the difference.
  Example: account balance at least the withdrawal amount.
- **Band** (`lo <= value <= hi`): compose two range proofs, one for
  `value - lo >= 0` and one for `hi - value >= 0`. Example: a price inside
  a collar, an age in a bracket.
- **Age / date** (`today - dob >= 18 years`): a floor predicate over a day
  count. Example: proving a client is over 18 without revealing birthdate.
- **Set membership** (`value in {allowed}`): not a range; implement as an
  OR-composition of equality proofs (the same CDS OR primitive used for
  the bit proofs in `rangeproof.py`) or a Merkle-inclusion proof against a
  governance-published set root. This is the main extension point the
  paper flags as future work; the range predicates above are complete
  today. Example: jurisdiction on an allowlist.
- **Boolean policy** (`A and B`, `A or B`): prove each atomic predicate and
  combine, or express the composition in one circuit. Start with
  independent proofs per clause; aggregate later if latency demands.

### Enforcement checklist (get these right or the guarantee leaks)

The cryptography only helps if the surrounding system is disciplined. From
the paper's threat model and source-integrity discussion:

- **Deny by default.** The governed action must be unreachable without a
  valid attachment. If an agent can hit the execution endpoint by another
  path, no proof system constrains it. Enforce with network policy or a
  gateway that owns the only route to the action.
- **Co-locate the prover with the source of truth**, or have the source
  sign the commitment. A proof binds the statement to the committed value;
  something must bind the committed value to your system of record.
  Without this, a compromised agent could prove a rule about a value it
  made up. (Topologies A and B in the paper.)
- **Bind the proof to the action.** The context includes an
  `action_ref`; a proof for one order must not authorize another. The
  prototype enforces this and tests it (`verify_e2e.py` scenario S4).
- **Keep the governance key off agent hosts.** Sign predicates in a
  reviewed pipeline with a key in a KMS/HSM; distribute only the public
  key to verifiers.
- **Treat the gateway as trusted and model-free.** Its value is that it
  contains no LLM and cannot be prompt-injected. Do not put model calls in
  the verification path.
- **Version predicates and plan migration windows.** Stale-version proofs
  fail closed by design; decide operationally what happens on failure
  (hard deny for trading, human escalation for support).

### What to build next for a production deployment

The prototype is complete as a demonstration; a production system adds:
transport authentication between agents and the gateway (mTLS or SPIFFE);
a real source-of-truth adapter with commitment signing; set-membership and
Boolean-composition predicate types; durable sharded audit storage; and
the E2 (Rust) engine wired in as the default prover. None of these change
the protocol or the guarantee; they harden the same design.

## How to verify the claims

The paper's security claims map to runnable checks:

1. **A false statement cannot be proved.** `tests_soundness.py` T1 shows the
   honest prover API refuses when notional > cap; T7 substitutes a
   non-binary bit commitment (an overflow attempt) and makes 2,000
   randomized forgery attempts against the OR-proof: expect 0 accepted.
2. **Tampering is detected.** T2 flips one response scalar and separately
   swaps two bit commitments; both must fail verification. The Rust engine
   check in `run_all.sh` stage 5 does the same against Bulletproofs.
3. **Proofs cannot be replayed.** T3 replays a valid proof under a
   different nonce, T4 under a different predicate version; both must fail.
   The proof is also bound to the action it authorizes: a proof produced
   for order `ord-9912` fails against `ord-7777` (the Fiat-Shamir
   transcript absorbs the full request context, including `action_ref`,
   before any commitment; see `rangeproof.py`).
4. **The audit trail is tamper-evident.** T6 edits one past entry and the
   hash chain check fails. You can re-verify any produced log yourself:
   `python3 -c "from zkgw.gateway import AuditLog; print(AuditLog.verify_chain('../results/audit_log.jsonl'))"`
5. **Nothing sensitive crosses the boundary.** Read the envelope printed by
   `demo_trading.py`: it contains a predicate id and version, a request
   context, a Pedersen commitment, and a proof. Grep the envelope and the
   audit log for the notional; it is not there.
6. **Proof sizes match the theory.** Bulletproofs sizes are deterministic:
   32*(9 + 2*log2(n)) bytes, i.e. 608 B at 32 bits and 672 B at 64 bits,
   independent of host. Timings vary with hardware; treat published
   timings as feasibility evidence and rerun `bench.py` on your machine.

## Setting up a governing entity (verifiable predicates)

The registry is what stops a compromised agent from defining its own loose
policy. Predicates are signed by a governance key; the gateway re-verifies
the signature on every read, so a tampered registry fails at use time.

As the governing entity (e.g., a risk or compliance team):

```bash
cd python

# 1. Generate the governance keypair. Keep the .secret file private
#    (production: a KMS/HSM, with signing in a reviewed release pipeline).
python3 governance_cli.py keygen --out keys/governance

# 2. Define and sign a policy predicate. This writes a signed JSON file
#    that IS the policy: identifier, version, type, parameters, owner.
python3 governance_cli.py define \
    --id pretrade_notional_cap --version 1 --type range_leq \
    --cap 1000000000 --nbits 32 --unit USD_cents \
    --owner risk-governance-team \
    --key keys/governance.secret --out registry/

# 3. Anyone can verify a predicate file against the PUBLIC key:
python3 governance_cli.py verify \
    --file registry/pretrade_notional_cap.v1.json --pub keys/governance.pub

# 4. Audit a whole registry directory:
python3 governance_cli.py list --dir registry --pub keys/governance.pub
```

Distribution rule: gateways receive the governance PUBLIC key out of band
(configuration, deployment image), never from the predicate files
themselves. Policy changes are new signed versions; version binding makes
proofs against stale versions fail closed, so plan migration windows.
Verification of a signed predicate can be done by any party holding the
public key; nothing about the check is private.

## Reproducing the paper's numbers

`bash experiments/run_all.sh` produces `results/execution_log.txt` with an
environment header (CPU model, vCPUs, RAM, toolchain versions) followed by
every stage's output and exit code. Published timings in the paper come
from a single-vCPU virtualized Xeon and are labeled as such; sizes and all
pass/fail outcomes are host-independent, timings are not. For an
apples-to-apples table, run the pipeline on your hardware and cite your
own environment line.

## Security status

This is a research prototype accompanying a paper, not a product. The
Python engine is readable and auditable but not constant-time; the Rust
engine uses the dalek Bulletproofs implementation. Only the `range_leq`
predicate type is wired end to end. No external security audit has been
performed. Do not use for real funds or real personal data.

## License

MIT. See LICENSE.

## Citation and provenance

If you use this work, cite the paper (BibTeX below once the arXiv ID is
live). This implementation was developed with AI assistance (Anthropic's
Claude). All results are reproducible from this repository.

```bibtex
@misc{gopalakrishna2026zkgateway,
  title={Zero-Knowledge Data Minimization for Multi-Agent AI Systems:
         A Proof-Verification Gateway Architecture for Data Privacy
         Between Agents},
  author={Subbabhatta Gopalakrishna, Ashok},
  year={2026},
  eprint={TBD},
  archivePrefix={arXiv},
  primaryClass={cs.CR}
}
```
