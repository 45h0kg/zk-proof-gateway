# Changelog

All notable changes to the containerization/deployment effort, in reverse
chronological order. See `IMPLEMENTATION_HLD.md`/`IMPLEMENTATION_LLD.md`
for full architectural detail and `Spec.md`'s status addendum for how this
relates to the original one-day spec.

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
