# Implementation HLD — Containerizing the ZK Proof Gateway

Companion to `Spec.md` (the original one-day containerization ask), `HLD.md`
(the paper's architecture), and `IMPLEMENTATION_LLD.md` (file-by-file
detail). This document describes the **as-built** system, not the original
plan — see `Spec.md`'s status addendum for how the two diverge and why.

---

## 1. What actually shipped, in one paragraph

The prover was split out of the in-process gateway into a real HTTP
service (`Spec.md`'s P0), exactly as asked, in Python first. Partway
through, the request shifted from "containerize the Python reference
engine" to "the network-facing services should be fast, not just correct" —
so P0's HTTP contract was re-implemented a second time in Go, proving via
a Rust Bulletproofs engine instead of the Python Sigma-OR engine. That
Go+Rust pair is what P1 (Docker), P2 (Helm), and P3 (Terraform) actually
containerize and deploy. The original Python `agent_server.py` /
`prover_service.py` remain in the repo as the paper's E1 reference
implementation — readable, dependency-light, intentionally not the
production path — but nothing in `docker/`, `helm/`, or `terraform/`
builds or ships them.

Three follow-on passes hardened what P0-P3 first produced: unit tests for
the pieces that previously only had end-to-end coverage, a real `kind`
cluster run that caught two genuine bugs template-rendering alone never
would have, and a security review that caught a real governance-key
exposure and a couple of DoS-shaped gaps. All of this is merged to `main`;
see `CHANGELOG.md` for the PR-by-PR record.

## 2. Two engines, one contract

```mermaid
flowchart LR
    subgraph E1["E1 -- Python reference (not deployed)"]
      PSV[prover_service.py] -->|Sigma-OR proof, ~500ms verify| ASV[agent_server.py]
    end
    subgraph E2["E2 -- Go+Rust (P1/P2/P3 deploy this)"]
      GOP[go/proverservice] -->|"exec: rust/zkrp prove"| RZ[rust/zkrp CLI]
      GOG[go/gatewayservice] -->|"exec: rust/zkrp verify"| RZ
      GOP -.same HTTP contract.-> GOG
    end
    RZ -->|Bulletproofs, ~2-8ms verify| GOG
```

Both engines expose the identical wire contract: `POST /prove` on the
prover, the same MCP-shaped JSON-RPC surface (`initialize`, `tools/list`,
`zk/context`, `tools/call`, `venue/orders`) plus `GET /healthz` on the
gateway. `python/verify_e2e.py` drives either pairing, or any mix of a
locally-run gateway with a networked prover, via three environment
variables: `ZKGW_PROVER_URL` (hit an external prover instead of proving
in-process), `ZKGW_GATEWAY_CMD` (spawn a different gateway binary), and
`ZKGW_GATEWAY_URL` (attach to an already-running gateway instead of
spawning one — what makes testing the persistent Docker/kind deployments
meaningful rather than re-proving the protocol against a throwaway
instance).

The Go gateway's Schnorr signature verification (`go/internal/predicate`)
replicates `zkgw.primitives.sign`/`sig_verify` exactly — same secp256k1
curve, same challenge hash, same point compression — so predicates signed
by the existing `governance_cli.py` verify unmodified against either
engine. The Go audit log (`go/internal/auditlog`) is byte-compatible with
Python's canonical-JSON hash chain in the same way: confirmed by having
Python's own `AuditLog.verify_chain` re-verify a log file the Go gateway
wrote. Governance predicate signing stays Python in both worlds — it is
never on a request path, and the whole point of hand-rolled Python crypto
there is that a human can read it without trusting a compiled toolchain.

## 3. A2A (Agent2Agent): the other binding

HLD.md's protocol-extension section always described the envelope as
fitting "MCP `tools/call` params **or** an A2A message part" — only the
first half existed until this pass. Both `agent_server.py` and
`go/gatewayservice` now speak the real A2A wire format (JSON-RPC methods
`message/send`/`tasks/get`/`tasks/cancel`, an Agent Card at
`GET /.well-known/agent.json`) on the exact same HTTP endpoint as the MCP
methods, sharing one verification chain, one audit log, and one orders
ledger:

```mermaid
flowchart LR
    subgraph shared["shared underneath either surface"]
      CTX["zk/context"] --> VER["processGovernedCall /\nprocess_governed_call"]
      VER --> AUD[(audit log)]
      VER --> LED[(orders ledger)]
    end
    MCP["tools/call\n(params.zk_attachment)"] --> VER
    A2A["message/send\n(Message data part)"] --> VER
    CARD["GET /.well-known/agent.json"] -.discovery, not verified.-> A2A
    LIST["tools/list\nx_zk_required"] -.discovery, not verified.-> MCP
```

Since A2A has no native "tool call" concept, the governed action's name
and arguments travel inside the same Message data part as the
`zk_attachment` itself: `{"skill": "submit_order", "arguments": {...},
"zk_attachment": {...}}` -- a convention of this repo, not part of the A2A
spec (which deliberately leaves the invocation payload
application-defined). Tasks complete synchronously (proof verification is
single-digit-to-low-hundreds of milliseconds depending on engine), so
`tasks/cancel` always errors with "already in terminal state" -- there is
never an in-flight task to actually cancel. See `HLD.md` section 5 for the
exact wire shapes side by side.

## 4. rust/zkrp: the cap-enforcement fix

The Rust engine existed before this effort but only proved "`v` fits in
`n` bits" — no `cap` parameter anywhere. `cmd_prove`/`cmd_verify` now
implement the actual `range_leq` reduction: `v` and `d = cap - v` are both
range-proved as one 2-aggregate Bulletproof, and the verifier derives
`C_d = cap*B - C_v` itself homomorphically rather than trusting a
prover-supplied commitment — the same construction as the Python E1
engine, just over ristretto255 instead of secp256k1. This was refactored
into pure `prove_range_leq()`/`verify_range_leq()` functions (no
`process::exit`, no printing) specifically so it could be unit-tested
directly; 7 `cargo test` cases cover the honest path and every adversarial
one (tamper, wrong context, lowered cap, over-cap refusal, bit-width
violation, malformed input).

## 5. Deployment topology

```mermaid
flowchart TB
    subgraph host["host / kubectl"]
      H["localhost:8752 (Docker) or\nkubectl port-forward (Helm)"]
    end
    subgraph net["internal-only network / prover pod"]
      PR["prover\nno published port, no Service\ndeny-ALL ingress NetworkPolicy"]
    end
    subgraph gw["gateway"]
      GW["gateway\n:8752 published/Serviced\nsame-namespace NetworkPolicy"]
      PVC[("audit PVC / bind mount\nsurvives restarts")]
    end
    BOOT["bootstrap (Python, one-shot)\ngovernance_cli.py keygen + define"] -->|"writes secret to a\nkeys-only path,\nNEVER given to gw/prover"| KEYS[("keys-only store")]
    BOOT -->|"writes pub key +\nsigned predicate"| REG[("registry\n(ConfigMap / bind mount)")]
    REG -->|read-only| GW
    GW <--> PVC
    H --> GW
    PR -.no path to host or gateway.-x H
```

Docker Compose and the Helm chart both implement the same shape, adapted
to each platform's idiom:

- **Docker Compose**: prover and gateway share one `internal: true`
  network; the gateway additionally joins a second, non-internal network
  *solely* so its own `ports:` mapping actually works — an
  `internal: true` network silently drops port publishing entirely, which
  is not obvious from the compose file syntax and was found by testing,
  not assumed. Registry and audit are host bind mounts (not anonymous
  volumes) so the demo's grep-for-the-private-value check can run directly
  from the host shell. The governance secret lives in a *third*,
  keys-only bind mount that is mounted into `bootstrap` alone — the
  gateway/prover images never see it.
- **Helm**: prover is a sidecar co-located with a placeholder
  source-of-truth container in one pod (the paper's topology A — the
  prover belongs next to the source of truth, not next to the gateway),
  with no Service of any kind exposing that pod. The gateway is a separate
  ClusterIP Deployment. The audit volume is a `PersistentVolumeClaim`, not
  an `emptyDir` — confirmed by deleting the gateway pod under load and
  checking prior entries survived. Two `NetworkPolicy` objects: deny-*all*
  ingress on the prover (the gateway never calls the prover directly in
  this protocol — the calling *agent* fetches from the prover, then
  separately submits to the gateway — so an allow-list naming the gateway
  would be the wrong policy), and same-namespace-only ingress on the
  gateway as defense-in-depth (the gateway does need to be reachable).
  Confirmed genuinely *enforced*, not just declared: watched the prover
  connection time out with the policy on and succeed with it disabled, on
  a real `kind` cluster.
- **Terraform**: `terraform/gke` and `terraform/eks` are minimal, unapplied
  reference modules — a small cluster plus a `helm_release` of the chart
  above. GKE's node pool requests least-privilege OAuth scopes
  (`devstorage.read_only`, `logging.write`, `monitoring`), not the full
  `cloud-platform` scope. Both modules note that local Terraform state is
  unencrypted and can hold a short-lived cluster auth token in plaintext —
  a remote, encrypted backend is recommended for anything beyond a
  disposable local run.

## 6. Security posture: what's hardened, what's still open

Hardened (see `CHANGELOG.md` for specifics):
- Governance secret key never reaches the gateway/prover's filesystem in
  either Docker or Helm (Helm never referenced it in the first place;
  Docker's bootstrap originally did, fixed in the security review pass).
- Both Go HTTP servers cap request bodies at 1 MiB (`http.MaxBytesReader`)
  — previously unbounded reads were a trivial memory-exhaustion DoS.
- The gateway's in-memory context map is TTL-swept (5 minutes) instead of
  growing for the lifetime of the process.
- Internal subprocess error detail (Rust CLI stdout/exit status) is logged
  server-side only, not echoed into JSON-RPC error responses.
- `automountServiceAccountToken: false` on both Helm Deployments — neither
  pod calls the Kubernetes API.
- The audit log now survives process restarts (the PVC/bind-mount fix) —
  and, separately, `auditlog.New()` no longer truncates an existing file on
  startup, which the PVC fix alone would not have caught, since the
  original Python `AuditLog.__init__` (which the Go code was ported from)
  had the identical bug.

Still open, explicitly deferred rather than silently dropped:
- **No transport authentication at all** between callers and
  gateway/prover — both speak plain HTTP. NetworkPolicy (Helm) and the
  internal-only network (Compose) restrict *who can route to* the pods,
  but nothing authenticates *which* caller is on the other end of an
  allowed connection. mTLS is the planned next step.
- **No HTTP server timeouts or graceful shutdown** on either Go service —
  `http.ListenAndServe` with zero-value `Server` has no
  read/write/idle/header timeouts (slowloris-class DoS is possible), and
  neither service handles SIGTERM to drain in-flight requests before
  exiting. Bundled with the mTLS work, since it's the same "harden the Go
  servers" theme and the same files.
- **Set-membership / boolean-composition predicate types remain stubs.**
  The README already documents this as the main deliberate extension
  point; extending it now, under time pressure, risks the same failure
  mode P3 explicitly avoided by skipping enclave integration — a
  half-finished new cryptographic construction is worse than an honestly
  documented gap. Boolean AND-composition and real multi-predicate
  aggregation (reusing the 2-aggregate construction already built for cap
  enforcement, generalized to more predicates) are in scope as a bounded,
  non-novel extension; full OR-composition/set-membership is not.
- **No observability** (metrics, structured logs beyond the one audit-entry
  log line), **no HA story** (`replicas: 1` hardcoded, no
  PodDisruptionBudget), **no image pinning by digest**, **no
  `readOnlyRootFilesystem`/dropped-capabilities `securityContext`**, and
  **no audit-log rotation or external shipping** — all real
  production-readiness gaps, all lower-urgency than the items above, not
  yet scheduled.
- **Attestation-bound proofs (§7 below) are validated against a mock
  attestation authority, not real Nitro Enclaves or GCP Confidential
  Space.** The protocol -- mutual binding, nonce unification, the 6-step
  verification chain -- is real and tested; the hardware root of trust is
  not. Swapping the mock for a real attestation call is the remaining
  step (`HLD.md` §7's "Validation strategy").
- **Audit log schema is unchanged by attestation.** The attestation digest
  and measurement are logged (server-side `log.Printf`, `verifyAttachment`
  in `gatewayservice/main.go`) but not appended to the hash-chained audit
  entry -- extending `auditlog.go`'s canonical, cross-language-byte-exact
  format (Python's `AuditLog` re-verifies Go-written entries, see §7 below)
  is a deliberately separate piece of work, not bundled into this pass.
- **Not wired into Docker/Helm/`verify_e2e.py`.** No bootstrap script
  registers a `prover_measurement` predicate in the demo stack, so the
  Docker Compose and Helm deployments run the unattested path exactly as
  before; the attested path is exercised by `cargo test`, `go test`
  (`gatewayservice/attestation_test.go`, `internal/zkrpclient`), and by
  hand against the real built binaries, not by the existing 19/19 E2E
  scripts.

## 7. Attestation-bound predicate proofs: the mock implementation

`HLD.md` §7 proposes fusing a hardware attestation with the predicate
proof so verifying one artifact certifies both the predicate and the
specific measured prover binary that produced the committed value. This
section is what was actually built to validate that protocol locally,
per §7's own "Validation strategy" -- a real, tested implementation
against a mock attestation authority, not yet run against real Nitro
Enclaves or GCP Confidential Space.

**Mock attestation authority** (`rust/zkrp/src/attestation.rs`): an
`AttestationDoc` shaped like Nitro's attestation (module_id, timestamp, a
PCR0-style measurement, nonce, user_data, signature) but with a simple
fixed-layout binary encoding instead of real CBOR/COSE, and a single
Ed25519 signature from a key derived from a fixed, publicly-known seed
instead of a hardware-rooted certificate chain. `current_measurement()`
is a fixed constant standing in for "this build's PCR0" -- not a real
measurement of any binary.

**Mutual binding, for real**: `prove_range_leq_attested` computes the
value commitment first, generates the attestation over it
(`report_data = SHA-384(commit_v || ctx)`, direction A), then absorbs
`SHA-256(attestation)` into the same Merlin transcript the Bulletproof
itself is built against (direction B) before any Fiat-Shamir challenge is
drawn. `verify_range_leq_attested` runs the 6-step chain from `HLD.md`
§7 (steps 1-5; step 6 is the caller's job): mock signature check,
measurement match (skipped, not weakened, when no expectation is
configured -- see below), nonce/context match, `report_data` match, then
proof verification under the attested transcript.

**CLI**: `zkrp attest-prove <nbits> <cap> <value> <ctx>`, `zkrp
attest-verify <nbits> <cap> <proof_hex> <commit_v_hex> <ctx>
<attestation_hex> <expected_measurement_hex>`, `zkrp attest-measurement`.
21 Rust unit tests cover the honest path and every substitution/tamper
case: wrong measurement, tampered attestation signature, nonce mismatch
(replay across contexts), a genuine but mismatched attestation swapped
onto a different proof, and the empty-expected-measurement skip path.

**Registry**: a new `prover_measurement` predicate type
(`go/internal/predicate`), signed by the same governance key and Schnorr
scheme as `range_leq` (`python/governance_cli.py`'s new
`define-measurement` subcommand), verified by a shared `verifySchnorr`
helper rather than duplicating the Schnorr math. `Registry` gains a
second store (`registry.go`'s `measStore`/`PublishMeasurement`/
`GetMeasurement`); the gateway's startup loader peeks each registry
file's `ptype` (`predicate.PeekPType`) to dispatch to the right parser.

**Gateway policy, opt-in per deployment**: `proverservice` now always
attests (`client.ProveAttested` instead of `client.Prove` in
`handleProve`) -- a real enclave doesn't get to opt out of proving what it
is on request. Enforcement is the gateway's decision, made in
`verifyAttachment`: if the envelope carries an attestation (which it now
always does), the gateway always verifies via the attested transcript --
anything else would fail to verify, since the proof was built against
that transcript. Whether the attestation's *measurement* is checked
against anything is separate: if a `prover_measurement@1` predicate is
registered, its value is passed as the expected measurement and a
mismatch denies; if none is registered, the attestation is still fully
validated (signature, nonce, report_data) but the measurement match is
skipped rather than enforced against nothing. Absent an attestation
entirely, `verifyAttachment` only denies if a measurement policy is
registered (attestation required); otherwise it falls back to the
original unattested `Verify` path unchanged, for any prover that predates
this work.

This distinction -- *validate the attestation you were given* vs.
*require and police a specific one* -- is what makes proverservice's
always-attest change backward compatible: a regression check
(`go/gatewayservice/attestation_test.go`'s
`TestProcessGovernedCall_NoMeasurementPredicateRegistered_FallsBackButStillAllows`)
exists specifically because an earlier version of this change verified
attested proofs under the *unattested* transcript whenever no measurement
predicate was registered, which fails every time (the transcripts
genuinely differ) -- caught by rerunning the full `experiments/run_all.sh`
suite, not by the unit tests written before that point.

## 8. Verification record

Every claim above has actually been run, not just reasoned about:

| What | How verified |
|---|---|
| Cap enforcement (Rust) | `cargo test` (7 cases) + manual CLI smoke tests |
| Schnorr verify (Go) matches Python | Unit test against a fixture signed by the real `governance_cli.py`, not self-generated |
| Audit hash chain (Go) matches Python | Python's own `AuditLog.verify_chain` re-verifies a Go-written log |
| Docker stack, both containers | `docker compose up --build`, healthy, full 5-scenario verifier against the *persistent* containers, both grep checks clean |
| Audit durability (Docker) | Restarted the gateway container mid-test, entries survived |
| `helm lint` / `helm template` | Both pass, including with real predicate content via `--set-file` |
| `helm install` on a real cluster | `kind` cluster: images built and loaded, chart installed, PVC bound, in-cluster verifier pod (mounting the same audit PVC) — 12/12 at ~2.5ms verify latency |
| NetworkPolicy enforcement | Empirically confirmed on that same `kind` cluster (not assumed) |
| Audit durability (Kubernetes) | Deleted the gateway pod mid-test on that cluster, entries and chain survived across the restart boundary |
| `terraform validate` / `fmt -check` | Both modules, including after the GKE OAuth-scope fix |
| CI | `.github/workflows/ci.yml` runs both engines' full E2E path plus all unit tests on every push |
| Attestation-bound proofs (mock) | `cargo test` (21 cases, incl. tamper/substitution), 3 new `gatewayservice` integration tests against the real built `zkrp` binary, real HTTP calls by hand against running `gateway-service`/`prover-service` for both the correct- and wrong-measurement cases, full `experiments/run_all.sh` (both engines, 19/19) rerun clean afterward |

`terraform apply` and any enclave/Confidential-Space work remain
unattempted — stated here plainly, matching the standard this whole effort
has tried to hold to: state exactly what ran versus what was only
linted/rendered/validated.
