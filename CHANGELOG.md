# Changelog

All notable changes to the containerization/deployment effort, in reverse
chronological order. See `IMPLEMENTATION_HLD.md`/`IMPLEMENTATION_LLD.md`
for full architectural detail and `Spec.md`'s status addendum for how this
relates to the original one-day spec.

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
