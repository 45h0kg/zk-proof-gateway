# Changelog

All notable changes to the containerization/deployment effort, in reverse
chronological order. See `IMPLEMENTATION_HLD.md`/`IMPLEMENTATION_LLD.md`
for full architectural detail and `Spec.md`'s status addendum for how this
relates to the original one-day spec.

## PR #10 — README staleness fixes

Four factual staleness issues in the README, fixed:

### Changed
- Repository layout: `helm/zk-proof-gateway/`'s status line said
  "lint/template-verified", contradicting the Kubernetes section a few
  paragraphs down (`helm install` has actually been run and verified on
  `kind`). Now says "installed + verified on kind".
- Paper title updated everywhere it appears (intro line + BibTeX) from
  "Zero-Knowledge Data Minimization for Multi-Agent AI Systems: A
  Proof-Verification Gateway Architecture for Data Privacy Between
  Agents" to the current title, "Zero-Knowledge Predicate Proofs Between
  AI Agents: A Measured, Cross-Protocol Gateway and the Source-Integrity
  Gap".
- Security status said "Only the `range_leq` predicate type is wired end
  to end", which PR #8 made false. Now names both `range_leq` and
  `prover_measurement`, with an explicit caveat that the attestation
  authority behind the latter is a mock with a publicly derivable root
  seed -- no hardware root of trust, no security property against a real
  adversary.
- New "Attestation-bound predicate proofs (experimental, mock only)"
  section: the README previously said nothing about PR #7/#8's work at
  all, so a reader scanning it would not learn it exists. Points at `zkrp
  attest-prove`/`attest-verify`/`attest-measurement`, the
  `prover_measurement` predicate, and `governance_cli.py
  define-measurement`, linked from the Security status section.

## PR #9 — Case-study legal grounding + Spec.md formatting cleanup

Replaces the case study's only US-specific regulatory reference (SEC
15c3-5) with an EU grounding that actually fits this project's thesis:
GDPR's data-minimisation principle, not a securities pre-trade rule. Also
reformats `Spec.md` into proper Markdown (real headers, bullet lists, code
fences) matching this changelog's style -- content otherwise unchanged,
confirmed by a normalized word-level diff against the prior version.

### Changed
- `python/demo_trading.py`: the case study's private notional is now
  framed as a retail client's order -- personal data under GDPR, since it
  relates to an identifiable person. Docstring cites GDPR Art. 5(1)(c)
  (data minimisation) + Art. 25 (protection by design/default) as the
  primary grounding (this is literally the project's thesis), GDPR Art. 22
  (automated decision-making) and the EU AI Act's Art. 12 record-keeping
  duty as narrower, explicitly hedged fits (neither asserted to apply to
  any given deployment), and MiFID II Art. 17 / RTS 6 for why a pre-trade
  notional cap exists as a business rule in the first place. All
  SEC/FINRA references removed (there was exactly one, in this file).
- `Spec.md`: reformatted from plain prose with ALL-CAPS pseudo-headers into
  real Markdown (`##` headers, bullet lists, `` `code` `` spans, ` ```bash `
  fences for commands) -- no wording changes beyond what the reformat
  itself required. Added one new paragraph to the status addendum noting
  PR #7/#8 (attestation-bound proofs), which had landed but weren't yet
  reflected there.

### Verified
- `python3 demo_trading.py` still runs end-to-end: ALLOW decision, audit
  chain intact, negative scenario still refuses to prove.
- Repo-wide grep for `SEC`/`FINRA`/`15c3-5`: zero hits.
- `Spec.md` content check: normalized (markdown-stripped) word-level diff
  against the pre-reformat version shows only case changes in the old
  ALL-CAPS headers and the one deliberately added status-addendum
  paragraph -- nothing else changed.

## PR #8 — Attestation-bound predicate proofs (mock implementation)

Implements PR #7's design against a local mock attestation authority
(HLD.md §7's "Validation strategy") -- real code and tests, not yet real
Nitro Enclaves or GCP Confidential Space hardware. Go+Rust only.

### Added
- `rust/zkrp/src/attestation.rs` (new file): mock enclave attestation --
  Ed25519-signed document over module_id/timestamp/measurement/nonce/
  user_data, with a fixed publicly-derivable "root" seed standing in for
  a hardware root of trust. 6 unit tests.
- `rust/zkrp`: `attest-prove`/`attest-verify`/`attest-measurement` CLI
  subcommands implementing the mutual binding (report_data commits to the
  proof, the Merlin transcript commits to the attestation) and the 6-step
  verification chain, including an empty-expected-measurement skip path
  for when no policy is configured. 14 new unit tests (21 total).
- `go/internal/predicate`: `MeasurementPredicate`/`MeasurementParams`,
  `PeekPType`, `ParseMeasurementDoc` -- a governance-signed
  `prover_measurement` predicate type, parallel to `range_leq` rather than
  a generalized params representation. Shared `verifySchnorr` helper.
- `go/internal/zkrpclient`: `ProveAttested`/`VerifyAttested`/
  `CurrentMeasurement`, wrapping the new CLI subcommands.
- `go/gatewayservice/registry.go`: a second predicate store
  (`measStore`/`PublishMeasurement`/`GetMeasurement`).
- `go/gatewayservice`: startup registry loading now dispatches on `ptype`;
  `verifyAttachment` always verifies an attested envelope via the attested
  transcript, checks the measurement against a registered
  `prover_measurement@1` predicate when one exists, and otherwise falls
  back to the original unattested path unchanged.
- `go/proverservice`: `handleProve` always attests now.
- `python/governance_cli.py`: `define-measurement` subcommand, signing
  `prover_measurement` predicates the same way `define` signs `range_leq`.
- Three new Go test files (`gatewayservice/attestation_test.go`,
  `internal/zkrpclient/zkrpclient_test.go`, plus fixtures added to
  `internal/predicate/predicate_test.go`), one of them a regression test
  for a transcript-mismatch bug found and fixed during this work (see
  Fixed, below).
- `HLD.md` §7, `IMPLEMENTATION_HLD.md` (new §7), `IMPLEMENTATION_LLD.md`
  (new section): updated from "design only" to as-built detail.

### Fixed
- **Found during this work, not shipped**: an early version had
  `proverservice` always attest (binding the attestation digest into the
  proof's own transcript) while the gateway only used the attested
  verify path when a `prover_measurement` predicate was registered --
  meaning every proof failed to verify whenever no such predicate existed
  (the transcripts genuinely differ). Caught by rerunning
  `experiments/run_all.sh` after the change (both engines dropped from
  19/19), not by the unit tests written up to that point. Fixed by making
  the *transcript choice* follow whether the envelope carries an
  attestation (always, currently) while the *measurement policy* stays
  registry-driven and independent -- see `IMPLEMENTATION_LLD.md`.

### Known, deferred (not fixed here)
- Audit-log schema unchanged: attestation digest/measurement are logged,
  not hashed into the audit chain.
- No Docker Compose/Helm bootstrap registers a `prover_measurement`
  predicate -- the existing demo stacks and `verify_e2e.py`'s 19/19 keep
  exercising the unattested path exactly as before.
- Real Nitro Enclaves/GCP Confidential Space integration: unattempted.

### Verified
- `cargo test` (21 cases) + `cargo build --release`.
- `go build ./...`, `go vet ./...`, `go test ./...` (all packages,
  including the new integration tests against the real release binary).
- A real `governance_cli.py define-measurement` run, verified by this Go
  code.
- Manual end-to-end HTTP calls against real running `gateway-service`/
  `prover-service` processes: correct-measurement ALLOW, wrong-measurement
  DENY, no-policy-registered ALLOW.
- Full `experiments/run_all.sh` rerun clean afterward, both engines 19/19.

## PR #7 — Attestation-bound predicate proofs (design)

Docs-only. Proposes fusing a hardware attestation (AWS Nitro Enclaves / GCP
Confidential Space) with the predicate proof so verifying one artifact
certifies both the predicate and the specific measured binary that read
the committed value, closing the source-integrity gap `HLD.md` §6/§11
name but don't answer. No code changes.

### Added
- `HLD.md` new §7: mutual binding (`report_data` commits to the proof,
  the Fiat-Shamir/Merlin transcript commits to the attestation), nonce
  unification between `zk/context` and the enclave attestation call, the
  6-step gateway verification chain, a `prover_measurement` governance
  predicate type, the open enclave-I/O (vsock) problem, expected
  attestation-vs-proof size/latency shape, and a pin-the-measurement
  policy for audit replay across prover upgrades. Sections 7-10 renumbered
  to 8-11 to make room.
- `IMPLEMENTATION_HLD.md` §6: one cross-reference bullet in the "still
  open" list pointing at the new `HLD.md` §7.

### Verified
- Design-stage only; no code, no tests, no deployment changes in this PR.

## PR #6 — A2A (Agent2Agent) protocol surface

Adds the other binding `HLD.md`'s protocol-extension section always
described but never implemented ("fits in MCP `tools/call` params or an
A2A message part"). Both gateways now speak real A2A wire format
alongside the existing MCP-shaped methods, on the same HTTP endpoint,
sharing one verification chain, audit log, and orders ledger.

### Added
- `go/gatewayservice/a2a.go` + `python/agent_server.py`: `message/send`,
  `tasks/get`, `tasks/cancel`, and an Agent Card at
  `GET /.well-known/agent.json`. The governed action's name/arguments
  travel in a Message data part alongside `zk_attachment`
  (`{"skill", "arguments", "zk_attachment"}` — this repo's own convention;
  A2A leaves that payload application-defined). Tasks complete
  synchronously, so `tasks/cancel` always errors.
- `go/gatewayservice/a2a_test.go`: unit tests for the pure helpers and the
  two fast-fail paths that don't need a live registry or `zkrp` binary.
- `verify_e2e.py`: seven new checks covering the Agent Card, `message/send`
  ALLOW + deny-by-default, `tasks/get`, `tasks/cancel`, and the shared
  ledger — deliberately not re-running every MCP adversarial case a second
  time, since the verification chain underneath is the same shared
  function already covered by S1-S5.

### Changed
- Refactored `handleToolsCall`/`tools/call`'s entire verification chain
  into a protocol-agnostic `processGovernedCall`/`process_governed_call`
  in both gateways, so MCP and A2A share one implementation instead of
  two. No MCP behavior change — reran every existing scenario before and
  after.

### Verified
- Both engines: all 19 checks (`cargo test`, `go test`, full
  `verify_e2e.py`) pass — in-process Python, networked Python, and Go+Rust.
- Rebuilt and reran against the real docker-compose stack; both required
  greps for the private value still zero hits.
- Not reverified against a live `kind` cluster — PR #3's cluster numbers
  predate this addition.

## PR #5 — Fix Mermaid/Markdown rendering bugs in docs

- `HLD.md`'s Section V sequence diagram still failed to render after an
  earlier fix — the real cause was Mermaid treating `;` as a statement
  separator in message text (not the `<=` operator the earlier fix
  addressed). Replaced the semicolon with a comma.
- `CHANGELOG.md` still said `[Unreleased] — security review` after that
  work was merged as PR #4 — retitled to match the other entries.
- `Spec.md`'s status addendum: an ASCII `====` banner sat directly below
  its heading text with no blank line, triggering Markdown's Setext H1
  syntax and rendering as an oversized, out-of-place heading. Replaced
  with a normal `##` header; also cleaned up an invalid `2b.` list item.
- `README.md`: tidied the citation section wording.

## PR #4 — Security review + design doc refresh

Dedicated security pass over the Go/Docker/Helm/Terraform surface added by
the three PRs below — not the crypto itself, which the soundness suite
already covers.

### Fixed
- **Governance secret key was reachable inside the gateway container's
  mounted filesystem** in the Docker Compose deployment (bootstrap wrote
  `governance.secret` into the same directory bind-mounted read-only into
  the gateway). Split into a separate keys-only bind mount that is never
  given to the gateway or prover. `verify_e2e.py` gained a `ZKGW_KEYS_DIR`
  env var (test-tooling only need, distinct from anything the deployed
  services require).
- Unbounded request bodies on both Go HTTP servers — capped at 1 MiB via
  `http.MaxBytesReader`.
- Unbounded growth of the gateway's in-memory context map — added a
  5-minute TTL and a background sweeper.
- Internal subprocess error detail (Rust CLI stdout/exit status) was being
  echoed into caller-facing JSON-RPC error messages — now logged
  server-side only.
- GKE Terraform module requested the full `cloud-platform` OAuth scope for
  its node pool — narrowed to `devstorage.read_only` + `logging.write` +
  `monitoring`.
- Docker Compose's bootstrap used `chmod 777` (world-writable) on the
  audit directory — switched to `chown 1000:1000`, the actual uid that
  needs write access.
- `HLD.md`'s Section V sequence diagram failed to render on GitHub
  (Mermaid's parser chokes on `<=` inside message text) — replaced with
  Unicode `≤`.

### Added
- `automountServiceAccountToken: false` on both Helm Deployments.
- A Terraform-state-security note in both module READMEs (unencrypted
  local state can hold a short-lived cluster auth token in plaintext).

### Known, deferred (not fixed here)
- No transport authentication (mTLS) between callers and gateway/prover.
- No HTTP server timeouts or graceful shutdown on the Go services.
- Set-membership/boolean-composition predicate types remain stubs.

## PR #3 — Durable audit PVC + real `kind` cluster verification

- Gateway's audit volume changed from `emptyDir` to a `PersistentVolumeClaim`
  (`helm/zk-proof-gateway/templates/audit-pvc.yaml`,
  `gateway.audit.persistence.*` values).
- **Found via the real cluster test, both fixed:**
  - `go/internal/auditlog.New()` (and the Python `AuditLog.__init__` it was
    ported from) unconditionally truncated the audit file on every process
    start — meaning the PVC fix alone would have bought nothing. Both now
    resume the hash chain from the last entry instead.
  - `values.yaml`'s `prover.sourceValue` was a bare YAML integer, which
    Helm's YAML→JSON→`interface{}` pipeline renders in scientific notation
    (`"7.35e+08"`) for large values — broke the prover's `strconv.ParseInt`.
    Now a quoted string.
- **Verified for the first time against a real cluster** (`kind`), not
  just `lint`/`template`: images built and loaded in, chart installed with
  a real governance-signed predicate, both pods healthy, PVC bound,
  in-cluster verifier — 12/12 at ~2.5ms verify latency. Confirmed
  `kindnet` genuinely enforces both NetworkPolicies (prover connection
  times out with the policy on, succeeds with it disabled). Confirmed
  audit durability by deleting the gateway pod mid-test.

## PR #2 — Unit tests + defense-in-depth NetworkPolicy

- `rust/zkrp`: refactored `cmd_prove`/`cmd_verify` into pure, testable
  functions; 7 new `cargo test` cases covering the cap-enforcement logic
  directly.
- `go/internal/{predicate,auditlog,zkctx}`: new unit tests, notably one
  verifying a real signature produced by Python's `governance_cli.py`
  (fixture, not self-generated).
- `helm/zk-proof-gateway/templates/gateway-networkpolicy.yaml`: new,
  restricts ingress to the gateway pod to its own namespace — additive
  alongside the prover's existing deny-all policy.
- CI and `run_all.sh` both wired to run the new tests.

## PR #1 — Containerize: prover-as-a-service, Go+Rust stack, Docker/Helm/Terraform

Implements `Spec.md`'s P0-P3.

- **P0**: `python/prover_service.py` (new) — the prover as a real HTTP
  service, Python E1 engine. `verify_e2e.py` gained `ZKGW_PROVER_URL`
  (networked mode). Fixed `agent_server.py` binding to `0.0.0.0` (was
  hardcoded `127.0.0.1`) and added `GET /healthz`.
- **Mid-flight pivot**: prover and gateway re-implemented in Go
  (`go/proverservice`, `go/gatewayservice`), proving/verifying via a Rust
  Bulletproofs engine (`rust/zkrp`) instead of the Python engine. This
  required fixing a real gap in `rust/zkrp` first — it only proved
  bit-width membership, not actual cap enforcement. `verify_e2e.py` gained
  `ZKGW_GATEWAY_CMD`/`ZKGW_GATEWAY_URL` to drive either backend.
- **P1**: multi-stage Dockerfiles (Rust build stage + Go build stage) for
  gateway and prover; `docker-compose.yml` with the prover on a
  Docker-internal-only network; `.github/workflows/ci.yml`; the
  `.gitignore` `Spec.md` assumed already existed (it didn't).
- **P2**: Helm chart — prover sidecar with a placeholder source-of-truth
  container, gateway as a separate ClusterIP Deployment, a deny-all
  NetworkPolicy on the prover pod.
- **P3**: minimal, unapplied Terraform reference modules (`terraform/gke`,
  `terraform/eks`) — small cluster + `helm_release` of the P2 chart.
  Deliberately does not attempt Confidential Space or Nitro Enclaves.
