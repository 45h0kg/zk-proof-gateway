# Implementation LLD — Containerizing the ZK Proof Gateway

File-by-file detail for `IMPLEMENTATION_HLD.md`. This describes the code as
it exists on `main` today. Where the original plan (see `Spec.md`) called
for something different, that's noted inline rather than silently dropped.

---

## P0 — prover as an HTTP service

### Python engine (E1) — as originally specced

- **`python/prover_service.py`**: stdlib `http.server`, `POST /prove` +
  `GET /healthz`. `read_source_value()` reads `ZKGW_SOURCE_VALUE`
  (int, cents); `ZKGW_AGENT_ID` is read and printed at startup but not
  otherwise consumed (mirrors `agent_server.py`'s existing pattern — the
  context already carries the `prover` id). Refuses on predicate violation
  with HTTP 422 `{"error": "predicate violated"}`, translating
  `rangeproof.prove_range_leq`'s `ValueError`.
- **`python/governance_cli.py`**: gained `parse_predicate_doc(doc: dict)`,
  extracted from `load_predicate_file` so the over-the-wire path
  (`prover_service.py`, `verify_e2e.py`) and the file-based path share one
  parser.
- **`python/agent_server.py`**: `--host` flag (default `0.0.0.0`, was
  hardcoded `127.0.0.1` — unreachable from other containers or published
  ports) and a `GET /healthz` handler (the class previously only
  implemented `do_POST`).
- **`python/verify_e2e.py`**: three env vars, each independently optional:
  - `ZKGW_PROVER_URL` — obtain envelopes over HTTP from a running prover
    instead of calling `ExecutionAgent.prove()` in-process. `obtain_envelope()`
    translates a networked HTTP 422 into the same `ValueError` the
    in-process path raises, so call sites don't branch on mode.
  - `ZKGW_GATEWAY_CMD` — spawn a different gateway binary (e.g. the Go one)
    instead of `agent_server.py`, as long as it accepts the same
    `--port`/`--registry`/`--gov-pub`/`--audit` flags.
  - `ZKGW_GATEWAY_URL` — attach to an *already-running* gateway instead of
    spawning one at all (skips governance bootstrap too). Needs
    `ZKGW_REGISTRY_DIR` (predicate + governance pub key) and
    `ZKGW_AUDIT_PATH` (that gateway's real audit file) alongside it, plus
    optionally `ZKGW_KEYS_DIR` if the governance secret lives in a
    *different* directory than the registry (true for both the Docker and
    kind deployments, post-security-review — see P1/P2 below).
  - S5 (over-cap refusal) is re-parameterized in networked mode: rather
    than a second `ExecutionAgent` with a bigger private value (impossible
    against a prover with one fixed configured value), it signs an
    ephemeral, properly-signed predicate with a *lower* cap and confirms
    the prover refuses it — same property (`the prover must not produce a
    proof for a false statement`), different lever.

### Go+Rust engine (E2) — the pivot

- **`rust/zkrp/src/main.rs`**: `prove_range_leq(nbits, cap, value, ctx) ->
  Result<ProveOutput, ProveError>` and `verify_range_leq(nbits, cap,
  proof_hex, commit_v_hex, ctx) -> VerifyOutput` are pure functions (no
  I/O, no `process::exit`); `cmd_prove`/`cmd_verify` are thin CLI wrappers
  around them. CLI shape: `zkrp prove <nbits> <cap> <value> [ctx]` /
  `zkrp verify <nbits> <cap> <proof_hex> <commit_v_hex> [ctx]` — the
  `<cap>` parameter is new; the previous CLI only took `<nbits> <value>
  [ctx]` and proved nothing about a cap at all. 7 `#[cfg(test)]` cases.
- **`go/go.mod`**: module `zkgw`, one direct dependency
  (`github.com/decred/dcrd/dcrec/secp256k1/v4`) for secp256k1 point
  arithmetic — used only to replicate the governance signature scheme, not
  for any novel crypto.
- **`go/internal/predicate/predicate.go`**: `Predicate` struct,
  `ParseDoc`/`LoadFile`, `CanonicalBytes()` (hand-built `fmt.Sprintf`, not a
  generic JSON canonicalizer — deliberately narrow so it's provably
  byte-identical to Python's `json.dumps({...}, sort_keys=True)` for this
  one struct shape: sorted keys `owner, params{cap,nbits,unit},
  predicate_id, ptype, version`, `", "`/`": "` separators). `VerifySignature`
  replicates `zkgw.primitives.sig_verify` exactly: `a = z*G - e*pub`,
  `e2 = SHA256("zkgw/sig/v1|" + compress(a) + compress(pub) + msg) mod N`,
  `e == e2`. Point compression matches Python's `Point.compress()` (SEC1
  compressed form) via the decred library's native `SerializeCompressed()`.
  Tested against a real fixture signed by Python's `sign()`, not a
  self-generated one — the property that matters is "Go accepts what
  Python signs," not "Go's math is internally self-consistent."
- **`go/internal/auditlog/auditlog.go`**: byte-compatible canonical JSON
  (same sorted-key, same-separator scheme as `predicate.go`, applied to the
  11/12-field audit entry shape) so Python's `AuditLog.verify_chain` can
  re-verify a Go-written log unmodified. `New(path)` resumes the hash chain
  from the file's last `entry_hash` if it already has content, rather than
  truncating — this was a real bug (see the P2 section below), not a
  design choice from the start.
- **`go/internal/zkctx/zkctx.go`**: `Context` struct + `Canonical()`, a
  fixed-field-order re-encoding that's what actually gets bound into the
  Rust Merlin transcript at both prove and verify time — deliberately *not*
  a raw-bytes passthrough of whatever a client happened to send, so
  incidental JSON formatting can never affect whether a proof binds to its
  context.
- **`go/internal/zkrpclient/zkrpclient.go`**: `os/exec.Command` wrapper
  around the `zkrp` binary. No shell is invoked (`exec.Command` never
  shell-interprets argv), so there's no injection surface regardless of
  what characters appear in the canonical context string or hex payloads.
- **`go/proverservice/main.go`** / **`go/gatewayservice/main.go`**: full
  Go reimplementations of `prover_service.py` / `agent_server.py`'s HTTP
  surface, proving/verifying via `zkrpclient` instead of the Python engine.
  Both take `--host`, `--port`, `--zkrp-bin`, and a `--healthcheck` flag
  that self-probes `http://127.0.0.1:<port>/healthz` and exits 0/1 — used
  as the Docker `HEALTHCHECK` command so the final image needs no
  curl/wget. The gateway additionally takes `--registry`, `--gov-pub`,
  `--audit`. **The gateway never trusts an envelope's own claimed
  `cap`/`nbits`** for the actual verify call — always sources them from the
  registry-verified `Predicate`, never from the (attacker-reachable)
  `proof_b64` payload; trusting the latter would let a malicious prover
  verify against a cap of its own choosing.
- Request-handling hardening (added in the security review pass, not P0):
  both servers wrap the request body in `http.MaxBytesReader(w, r.Body,
  1<<20)` before decoding; the gateway's `state.contexts` map entries carry
  a `createdAt` timestamp and a background goroutine
  (`sweepExpiredContexts`, every `contextTTL/2` = 2.5 min) evicts entries
  older than 5 minutes; verification errors are logged server-side
  (`log.Printf`) and returned to the caller as a generic `"denied:
  verification error"` rather than embedding the underlying error (which
  could include the Rust subprocess's raw stdout).

---

## P1 — containers (`docker/`)

Both Dockerfiles are multi-stage (`rust:1-slim-bookworm` builder →
`golang:1.23-bookworm` builder → `debian:bookworm-slim` final), **not**
`python:3.12-slim` as the original spec assumed — that assumption predates
the Go+Rust pivot. Non-root (`USER app`, uid 1000), `HEALTHCHECK` shells
out to the binary's own `--healthcheck` flag (shell form, so
`$ZKGW_PORT` expands), `VOLUME ["/audit"]` on the gateway image only.

`docker/docker-compose.yml`:
- **Two networks**, not one: `internal` (`internal: true`; bootstrap,
  prover, and gateway all join it) plus `public` (gateway only). This is
  *required*, not stylistic — an `internal: true` network silently drops
  `ports:` publishing entirely, discovered by testing (the mapping showed
  up in `docker inspect`'s `HostConfig.PortBindings` but never in the live
  `NetworkSettings.Ports`) rather than assumed from the compose spec.
- **Three bind-mounted directories**, not two:
  `.demo-keys/` (bootstrap only — governance secret, `chown`'d to
  `1000:1000`, never mounted into gateway or prover), `.demo-registry/`
  (governance public key + signed predicate, mounted read-only into the
  gateway), `.demo-audit/` (gateway, read-write, `chown`'d to `1000:1000`
  by bootstrap). The original plan had governance secret and registry
  share one directory; the security review pass split them after finding
  the secret was reachable inside the gateway container's mounted
  filesystem, directly violating the root README's own "keep the
  governance key off agent hosts" rule.
- `bootstrap` runs `governance_cli.py keygen --out /keys/governance`,
  `governance_cli.py define ... --key /keys/governance.secret --out
  /registry`, then `cp /keys/governance.pub /registry/governance.pub` —
  idempotent via a file-existence check on the predicate JSON, against a
  stock `python:3.12-slim` image (no custom Dockerfile needed for it).
- Running the 5-scenario verifier against the *persistent* containers
  (not a throwaway instance spawned by `verify_e2e.py` itself) requires a
  one-off container attached to the `internal` network by its actual
  compose-derived name (confirm with `docker network ls`, don't assume
  `docker_internal`), passing `ZKGW_GATEWAY_URL=http://gateway:8752`,
  `ZKGW_PROVER_URL=http://prover:8753`, `ZKGW_KEYS_DIR=/keys`,
  `ZKGW_REGISTRY_DIR=/registry`, `ZKGW_AUDIT_PATH=/audit/audit_log.jsonl` —
  see `docker/README.md` for the exact command, which has actually been
  run, not aspirational.

`.github/workflows/ci.yml`: two jobs, `python` (soundness suite +
in-process `verify_e2e.py`) and `go-rust` (`cargo build --release`,
`cargo test --release`, `go test ./...`, build both Go binaries, then the
networked `verify_e2e.py` run against them). Both run on every push.

---

## P2 — Helm chart (`helm/zk-proof-gateway/`)

Templates, as built:

- **`prover-deployment.yaml`**: sidecar form — `source-placeholder`
  (configurable image, default `busybox:1.36`, `sleep infinity`) +
  `prover` in one pod. No Service template at all for this pod — combined
  with the deny-all `NetworkPolicy`, there is no inbound route to it by
  omission *and* by policy.
- **`gateway-deployment.yaml`** + **`gateway-service.yaml`**: ClusterIP.
  Audit volume is `persistentVolumeClaim: claimName:
  {{ .Release.Name }}-zkgw-audit` when `gateway.audit.persistence.enabled`
  (default `true`), falling back to `emptyDir` only if explicitly disabled
  (e.g. a disposable smoke-test cluster with no default StorageClass).
- **`audit-pvc.yaml`**: the `PersistentVolumeClaim` itself,
  `ReadWriteOnce`, size/storageClass from `values.yaml`. This template
  didn't exist in the original plan or the first Helm PR — added after a
  real `kind` cluster test showed an `emptyDir` silently loses the entire
  audit trail on pod restart/reschedule.
- **`registry-configmap.yaml`**: `governance.pub` (string) +
  `predicates` (map of filename → full signed-predicate JSON content),
  both populated via `--set-string`/`--set-file` at install time. Never
  references a secret — the governance signing key does not enter the
  Helm chart or its values at any point.
- **`networkpolicy.yaml`**: deny-**all** ingress to the prover pod. Read
  literally, `Spec.md` asked for "allow only from the gateway pod
  selector" — that's backwards for this protocol: the gateway never calls
  the prover directly (the *agent* fetches an envelope from the prover,
  then separately submits it to the gateway), so an allow-list naming the
  gateway wouldn't match the actual call graph. Deny-all is the correct
  reading of "deny-by-default ingress to the governed workload."
- **`gateway-networkpolicy.yaml`**: added in the hardening pass, not the
  original P2 PR. Restricts ingress to the gateway pod to its own
  namespace — additive defense-in-depth, since (unlike the prover) the
  gateway does need to be reachable.
- Both policies are **confirmed enforced**, not just declared: on a real
  `kind` v0.33.0 cluster, `kindnet` (its default CNI) genuinely blocks the
  prover connection with the policy on and allows it once temporarily
  disabled — this was not assumed from general knowledge about kindnet's
  NetworkPolicy support, which turned out to be outdated for this version.
- Both Deployments set `automountServiceAccountToken: false` (security
  review pass) — neither pod calls the Kubernetes API.
- **`values.yaml`** gotcha, found by the `kind` test: `prover.sourceValue`
  **must** be a quoted string (`"735000000"`), not a bare YAML integer.
  Helm's YAML→JSON→`interface{}` pipeline decodes all numbers as
  `float64`; a bare `735000000` rendered as `"7.35e+08"` in the template,
  which the Go prover's `strconv.ParseInt` then failed to parse. Smaller
  integers (ports) don't hit this because Go's default float formatting
  doesn't switch to scientific notation at that magnitude — this is
  specifically a large-integer trap.
- **`NOTES.txt`**: port-forward instructions for the gateway, plus an
  explicit, honest caveat that the deny-all policy means nothing outside
  the prover's own pod can reach it — including a verifier run from the
  operator's workstation — and what to do instead (an in-cluster
  Job/Pod, or temporarily `networkPolicy.enabled=false`).

Verified on a real `kind` cluster (not just `lint`/`template`): images
built and `kind load docker-image`d in, chart installed with a real
governance-signed predicate, both pods healthy, PVC bound, 5-scenario
verifier run as an in-cluster pod (mounting the same audit PVC, reaching
gateway via Service DNS and prover via its pod IP) — 12/12 at ~2.5ms
verify latency. Gateway pod deleted mid-test to confirm audit durability
across a real restart — confirmed, chain verifies across the boundary via
both Go's and Python's `verify_chain`. Cluster and images torn down after;
nothing from that session persists.

---

## P3 — Terraform (`terraform/gke/`, `terraform/eks/`)

Minimal, explicitly **unapplied** reference modules: small cluster (own
VPC for EKS; managed node pool for GKE) + `helm_release` of the P2 chart.
`terraform validate` and `terraform fmt -check` pass for both; no
`terraform apply` has been run against a real account.

Security-review deltas from the original modules:
- GKE's node pool requests `devstorage.read_only`, `logging.write`,
  `monitoring` — not the full `cloud-platform` OAuth scope the module
  originally had. A workload needing broader GCP access should get it via
  Workload Identity on its own pod service account, not the node's.
- Both modules' READMEs now note that local Terraform state is
  unencrypted and can hold a short-lived cluster auth token
  (`data.google_client_config`'s / `data.aws_eks_cluster_auth`'s `token`)
  in plaintext — recommending a remote, encrypted backend for anything
  beyond a disposable local run. Not implemented (that's a real backend
  decision for whoever actually applies this), just documented.

Deliberately does not touch Confidential Space or Nitro Enclaves — that
remains explicit follow-up-paper scope, not attempted here.

---

## A2A (Agent2Agent) surface

Added to both gateways, on the same HTTP endpoint as the existing
MCP-shaped methods, sharing one verification chain and one audit/orders
ledger. See `IMPLEMENTATION_HLD.md` §3 for the architecture; this is the
file-by-file detail.

- **`go/gatewayservice/main.go`**: `handleToolsCall` (MCP) was refactored
  so its entire verification chain -- tool/skill lookup, attachment
  presence + schema validation, context lookup/replay/match, action_ref
  match, predicate match, proof verification -- lives in one new function,
  `processGovernedCall(state, toolName, orderRef, zkAttachmentRaw)
  governedCallOutcome`. `handleToolsCall` now just calls it and formats an
  MCP result/error; the A2A handler below does the same with a different
  wire shape. No behavior change for MCP callers -- confirmed by rerunning
  every existing scenario before adding any A2A code.
- **`go/gatewayservice/a2a.go`** (new file): `message/send`, `tasks/get`,
  `tasks/cancel`, and the Agent Card handler. `handleMessageSend` extracts
  a data part shaped `{"skill", "arguments", "zk_attachment"}` from the
  incoming `Message` (this shape is this repo's own convention -- A2A
  deliberately leaves skill-invocation payloads application-defined), runs
  it through `processGovernedCall`, and returns a `Task` in `completed` or
  `failed` state. Tasks are stored in `VenueState.tasks` (a new field,
  swept by the same TTL goroutine that already existed for contexts, for
  the same resource-exhaustion reason) so `tasks/get` can retrieve them
  later. `tasks/cancel` always returns an error -- every task here
  completes synchronously inside `message/send`, so there is never an
  in-flight task to cancel.
- **`go/gatewayservice/a2a_test.go`** (new file): unit tests for the pure
  helpers (`trimDeniedPrefix`, `failedTask`/`completedTask` shape) and the
  two `handleMessageSend` fast-fail paths (no data part; missing
  `zk_attachment`, i.e. deny-by-default) that don't require a live
  registry or `zkrp` binary.
- **`python/agent_server.py`**: the identical refactor --
  `process_governed_call(state, tool_name, order_ref, att) -> dict` shares
  the same chain between `tools/call` (MCP) and the new
  `handle_message_send` (A2A). `agent_card(port)` returns the Agent Card
  dict; served at `GET /.well-known/agent.json` alongside the existing
  `/healthz` route. `VenueState.tasks` is a plain dict, same TTL-free
  simplicity as the rest of the Python reference implementation (the Go
  gateway is the one under DoS-hardening scrutiny; see
  `IMPLEMENTATION_HLD.md` §6 for why that asymmetry is acceptable --
  `agent_server.py` is never deployed).
- **`python/verify_e2e.py`**: seven new checks (Agent Card contents,
  `message/send` ALLOW + notional-absence, deny-by-default, `tasks/get`,
  `tasks/cancel`-on-terminal-task, shared-ledger) run against whichever
  gateway backend is under test, immediately after the five MCP scenarios
  and before the audit-chain checks. Deliberately does *not* re-run every
  MCP adversarial case through A2A too -- `processGovernedCall`/
  `process_governed_call` is the single shared implementation already
  covered by S1-S5, so doing that would test the same code path twice
  under two names rather than add real coverage; the new checks target
  only what's actually new (the wire shapes, the Agent Card, task
  lifecycle, the shared ledger).

Verified: both engines pass all 19 checks (`cargo test`/`go test` unit
tests plus the full `verify_e2e.py` run), including against the real
docker-compose stack (rebuilt and rerun for this, not assumed) with both
required greps for the private value still returning zero hits. Not
re-verified against a live `kind` cluster -- the P2 section's cluster
numbers above predate this addition.

---

## Attestation-bound predicate proofs (mock implementation)

`HLD.md` §7 / `IMPLEMENTATION_HLD.md` §7 for the design and architecture;
this is the file-by-file detail. Go+Rust only, matching this whole
effort's engine scope -- Python's E1 stays as the paper's readable
reference and is untouched by this work.

- **`rust/zkrp/src/attestation.rs`** (new file): the mock attestation
  authority. `current_measurement()` is a fixed SHA-384 constant standing
  in for a real PCR0; `AttestationDoc::generate(commit_v, ctx)` builds and
  Ed25519-signs a document over `{module_id, timestamp, measurement, nonce
  = ctx bytes, user_data = report_data(commit_v, ctx)}`; `verify_signature`/
  `check_measurement`/`check_nonce`/`check_report_data` are the per-field
  checks the verify path calls in order. `encode`/`decode`/`to_hex`/
  `from_hex` are a hand-rolled fixed-layout binary format (length-prefixed
  strings, fixed-width fields) -- no serde dependency, matching this
  crate's existing style. 6 unit tests.
- **`rust/zkrp/src/main.rs`**: `transcript_attested(ctx, attestation_digest)`
  extends the existing `transcript(ctx)` with one more
  `append_message(b"attestation", ...)` call. `prove_range_leq_attested`
  computes the Pedersen commitment itself (via `pc.commit(...)`, not via
  `prove_multiple`'s return value) *before* building the attestation and
  the transcript -- report_data needs the real commitment, and the
  transcript must absorb the attestation before any Fiat-Shamir challenge
  is drawn; `debug_assert_eq!` checks the independently-computed
  commitment matches what `prove_multiple` returns.
  `verify_range_leq_attested` runs the 6-step chain; an empty
  `expected_measurement_hex` skips the measurement-match step entirely
  (rather than failing to decode it) so a gateway with no registered
  `prover_measurement` predicate can still verify a fully-consistent
  attestation without policing which binary produced it. New CLI
  subcommands `attest-prove`/`attest-verify`/`attest-measurement`. 14 new
  unit tests on top of the 7 already there (21 total): honest roundtrip,
  wrong measurement, tampered attestation signature, nonce mismatch
  (replay across contexts), a genuine attestation for one proof swapped
  onto a different one (report_data catches it), tampered proof under the
  attested path, malformed attestation, and the empty-measurement skip.
- **`rust/zkrp/Cargo.toml`**: two new dependencies, `sha2` (SHA-256/384)
  and `ed25519-dalek` v2 (signing). No version conflicts with the existing
  `curve25519-dalek-ng`/`bulletproofs`/`merlin` stack -- confirmed by a
  clean `cargo build`/`cargo test`/`cargo build --release`.
- **`go/internal/predicate/predicate.go`**: new `MeasurementParams`/
  `MeasurementPredicate` types and `PeekPType`/`ParseMeasurementDoc`/
  `LoadMeasurementFile`, parallel to the existing `Params`/`Predicate` for
  `range_leq` rather than generalizing it -- a generic `map[string]any`
  params representation would have needed a general canonical-JSON
  encoder matching Python's `json.dumps(sort_keys=True)` for arbitrary
  nested values (including the known large-integer/float-formatting trap
  from the Helm work), which the existing fixed-format-string
  `CanonicalBytes` approach sidesteps entirely by being type-specific. The
  Schnorr verify math itself was extracted into a shared `verifySchnorr`
  helper so both predicate types call the identical, already-tested logic
  rather than duplicating it.
- **`go/internal/predicate/predicate_test.go`**: a second real-signature
  fixture (`measFixture*`), generated the same way as the existing
  `range_leq` fixture -- a real `python3 governance_cli.py
  define-measurement` run against a throwaway keypair, not self-signed --
  covering accept/reject-tamper/canonical-bytes/PeekPType/round-trip-parse
  for the new type.
- **`go/internal/zkrpclient/zkrpclient.go`**: `ProveAttested`/
  `VerifyAttested`/`CurrentMeasurement`, wrapping the three new CLI
  subcommands the same way `Prove`/`Verify` already wrap `prove`/`verify`.
- **`go/internal/zkrpclient/zkrpclient_test.go`** (new file): tests against
  the real built `zkrp` release binary (skips, rather than fails, if it
  isn't built) -- honest roundtrip, wrong measurement denied, context
  mismatch denied, over-cap still refuses to prove under the attested path
  too.
- **`go/gatewayservice/registry.go`**: `Registry` gains a second store,
  `measStore`, plus `PublishMeasurement`/`GetMeasurement` mirroring
  `Publish`/`Get` -- same re-verify-signature-on-every-read defense against
  a tampered registry file.
- **`go/gatewayservice/main.go`**: the registry-loading loop at startup now
  peeks each file's `ptype` (`predicate.PeekPType`) before choosing which
  parser to use, so a `prover_measurement` doc dropped into the same
  registry directory as `range_leq` predicates loads correctly instead of
  silently mis-parsing into the wrong struct shape. `proofPayload` gained
  an optional `attestation_hex` field. `verifyAttachment`'s policy, in
  order: if the registry has a `prover_measurement@1` predicate, its value
  becomes the expected measurement passed to `VerifyAttested`; if the
  envelope carries an attestation (which every current prover always
  produces), it is *always* verified via the attested transcript,
  regardless of whether a measurement policy is registered -- the
  alternative (falling back to the plain transcript when no policy is
  configured) doesn't verify at all, since the proof was built with the
  attestation absorbed; if no attestation is present at all, the call is
  only denied when a measurement policy actively requires one, otherwise
  it falls back to the original unattested `Verify` path unchanged. The
  attestation digest and measurement are logged (`log.Printf`) alongside
  the existing audit line, not added to the hash-chained audit entry --
  see `IMPLEMENTATION_HLD.md` §6 for why that's a deliberately separate
  piece of work.
- **`go/gatewayservice/attestation_test.go`** (new file): three integration
  tests against the real built `zkrp` binary and a real two-predicate
  registry (one `range_leq`, one `prover_measurement`, both signed by the
  same throwaway governance key so the registry's single pubkey actually
  verifies both) -- correct measurement allows, wrong measurement denies,
  and no measurement policy registered still allows (this last one is the
  regression test for the transcript-mismatch bug found while building
  this: an earlier version fell back to the *unattested* transcript
  whenever no policy was registered, which fails every attested proof
  unconditionally, since `proverservice` always attests now).
- **`go/proverservice/main.go`**: `handleProve` calls `ProveAttested`
  instead of `Prove` and includes `attestation_hex` in the envelope
  payload unconditionally -- a real enclave doesn't get to opt out of
  proving what it is on request; whether anyone checks the attestation is
  the gateway's policy decision, not the prover's.
- **`python/governance_cli.py`**: `cmd_define`'s document-writing logic was
  factored out into `_write_predicate_doc` and reused by a new
  `cmd_define_measurement` / `define-measurement` subcommand, which signs
  a `prover_measurement` predicate (`{"algo", "measurement_hex"}` params)
  the same way `define` signs a `range_leq` one. `cmd_list`/`cmd_verify`
  needed no changes -- `Predicate.params` was already a free-form dict on
  the Python side.

**Deliberately not done in this pass** (see `IMPLEMENTATION_HLD.md` §6):
the audit-log schema is unchanged (attestation fields are logged, not
hashed into the chain); no Docker Compose/Helm bootstrap step registers a
`prover_measurement` predicate, so the existing demo stacks and
`verify_e2e.py`'s 19/19 continue to exercise the unattested-policy path
exactly as before; real Nitro Enclaves/GCP Confidential Space integration
remains unattempted, per `HLD.md` §7's validation strategy.

Verified: `cargo test` (21 cases) and `cargo build --release`; `go build
./...`, `go vet ./...`, `go test ./...` (including the 3 new
`gatewayservice` integration tests and 4 new `zkrpclient` tests against the
real release binary); a real `governance_cli.py define-measurement` run
producing a signature this Go code actually verifies; manual end-to-end
HTTP calls against real running `gateway-service`/`prover-service`
processes for the correct-measurement (ALLOW), wrong-measurement (DENY),
and no-policy-registered (ALLOW, unattested-fallback-would-have-failed)
cases; a full `experiments/run_all.sh` rerun afterward, both engines still
19/19.

---

## Cross-cutting: what changed vs. `Spec.md`'s literal text

- **Prover/gateway language**: Python as specced for P0, then Go+Rust for
  the actual container/Helm/Terraform deployment — a mid-flight redirect
  from the requester, not a unilateral substitution. Python's E1 engine
  stays in the repo as the paper's readable reference implementation.
- **`.gitignore`**: `Spec.md` assumed one already existed excluding
  `python/keys/`/`python/registry/`. It didn't exist at all; created here,
  and extended repeatedly as new directories needing exclusion appeared
  (`docker/.demo-keys/`, `terraform/**/.terraform/`, etc.).
- **Root README's "Kubernetes section"**: `Spec.md` asked to replace
  placeholder image names in an existing section. No such section existed
  yet (P2 hadn't been built). Added fresh, with real image names and a
  link to the chart, once P2 existed.
- **NetworkPolicy shape**: as detailed above — deny-all on the prover, not
  an allow-list naming the gateway, because that's what actually matches
  this protocol's call graph.
- **Everything in §6 of `IMPLEMENTATION_HLD.md`** ("still open"): real
  gaps, tracked, not silently dropped.
