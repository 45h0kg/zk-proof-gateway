SPEC: One-Day Containerization — ZK Proof Gateway

Target: executable by Claude Code, spec to PR, in one working day.

PRIORITY ORDER (do in this sequence; stop when time runs out)

P0 splits the prover into a real network service — required for any honest containerization, and it makes the architecture match the paper. P1 Dockerfiles + compose — makes the README's deployment claims real. P2 Helm chart + NetworkPolicy — the deny-by-default story, deployable. P3 Terraform — stretch only. Skip without guilt if the day is gone.

Everything below P1 is optional. P0 and P1 are the ones that matter, because they make the demo video reproducible by anyone.

CURRENT STATE (do not break these)

Existing behavior that must still pass after all changes:

python/tests_soundness.py -> "SOUNDNESS SUITE: 11/11 checks passed"
python/verify_e2e.py -> "AGENTIC PROTOCOL E2E: 12/12 checks passed"
bash experiments/run_all.sh -> all six stages exit 0
python/demo_trading.py -> prints envelope, decision ALLOW

Architecture note: today agent_server.py holds the gateway in-process and verify_e2e.py constructs ExecutionAgent locally. The paper describes the prover as a separate sidecar co-located with the source of truth. P0 closes that gap.

P0 — PROVER AS AN HTTP SERVICE

New file: python/prover_service.py

A minimal HTTP service wrapping the existing prover. Mirror the style of agent_server.py (stdlib http.server, JSON over POST, no frameworks).

Endpoints:

POST /prove
Request body: {"predicate": {...}, "context": {...}} where predicate is the same signed-predicate dict shape loaded by governance_cli.load_predicate_file, and context is the dict issued by the gateway's zk/context.
Behavior: read the private value from the configured source (see below), call rangeproof.prove_range_leq, return the envelope produced by gateway.make_envelope.
On predicate violation (value outside range): return HTTP 422 with {"error": "predicate violated"}. The service must NOT produce a proof for a false statement. This preserves scenario S5.
GET /healthz -> {"status": "ok"}

Source of the private value (keep simple, configurable):

Env var ZKGW_SOURCE_VALUE (integer, cents) for the demo.
Env var ZKGW_AGENT_ID (default exec-agent-07).
Structure the read behind a single function read_source_value() so a real OMS adapter can replace it later. Add a short docstring saying so.

CLI: python3 prover_service.py --port 8753

Modify: python/verify_e2e.py

Add an optional mode selected by env var ZKGW_PROVER_URL.
If unset: current in-process behavior (unchanged, still 12/12).
If set: obtain envelopes by POSTing to the prover service instead of calling ExecutionAgent.prove directly. All five scenarios must still pass, including S5 (which now expects HTTP 422 rather than a local ValueError).
Print which mode it ran in.

Acceptance:

python3 verify_e2e.py still prints 12/12 (in-process mode).
With prover service running and ZKGW_PROVER_URL set, verify_e2e.py again prints 12/12 (networked mode).
No change to soundness suite results.
P1 — CONTAINERS

New: python/requirements.txt Core library and services are stdlib-only. bench.py needs matplotlib and numpy. Pin loosely:

matplotlib>=3.8
numpy>=1.26

Note in a comment that the gateway and prover images do not need these.

New: docker/Dockerfile.gateway

Base python:3.12-slim.
Copy python/ only. No build tools needed (stdlib crypto).
Non-root user. USER app.
Entrypoint runs agent_server.py with args from env: ZKGW_PORT (default 8752), ZKGW_REGISTRY (default /registry), ZKGW_GOV_PUB (default /registry/governance.pub), ZKGW_AUDIT (default /audit/audit_log.jsonl).
HEALTHCHECK hitting a health endpoint. Add GET /healthz to agent_server.py returning {"status":"ok"} if not present.
Declare VOLUME /audit.

New: docker/Dockerfile.prover

Same base and hardening.
Entrypoint runs prover_service.py, port from ZKGW_PORT (default 8753).
Reads ZKGW_SOURCE_VALUE, ZKGW_AGENT_ID.

New: docker/docker-compose.yml Three-part local demo:

bootstrap (run-once): uses the gateway image to run governance_cli.py keygen and governance_cli.py define for pretrade_notional_cap@v1 (cap 1000000000, nbits 32, unit USD_cents), writing into a shared registry volume. Must be idempotent — skip if the predicate file already exists.
prover: prover image, ZKGW_SOURCE_VALUE=735000000, NOT exposed to the host (internal network only — this is the point: the value never leaves its trust cell).
gateway: gateway image, exposes 8752, mounts the registry volume read-only and an audit volume read-write.

Networks: put prover and gateway on an internal network. Only gateway publishes a port. Add a comment in the compose file saying this models the paper's trust boundary.

New: docker/README.md (short) Exact commands to run the demo end to end:

docker compose -f docker/docker-compose.yml up --build -d
ZKGW_PROVER_URL=http://localhost:8753 python3 python/verify_e2e.py   # or run inside
docker compose -f docker/docker-compose.yml logs gateway
docker compose -f docker/docker-compose.yml down -v

Adjust to whatever actually works after implementation; the README must contain commands that have been run and verified, not aspirational ones.

Modify: root README.md

Replace the placeholder image names (your-registry/zkgw-prover, your-registry/zkgw-gateway) in the Kubernetes section with the real image names built here.
Add a short "Run with Docker" subsection pointing at docker/README.md.

Acceptance:

docker compose up --build brings up all services healthy.
The full five-scenario verifier passes against the containerized stack.
docker compose logs gateway shows PASS and FAIL audit entries.
Grep the gateway logs and audit volume for 735000000 -> no hits. Add this as an explicit check in docker/README.md.
P2 — HELM CHART

New: helm/zk-proof-gateway/ Standard layout: Chart.yaml, values.yaml, templates/.

Templates:

prover-deployment.yaml — prover container. No Service exposing it externally; ClusterIP only, or run as a sidecar in the same pod as a placeholder source container to model co-location. Prefer the sidecar form: it matches the paper and is the stronger story.
gateway-deployment.yaml + gateway-service.yaml — ClusterIP.
registry-configmap.yaml — mounts signed predicate JSON. Values should allow supplying predicate files and the governance public key.
networkpolicy.yaml — the important one. Deny-by-default ingress to the governed workload; allow only from the gateway pod selector. Include a comment tying it to the paper's governed-channel assumption.
NOTES.txt — prints how to port-forward and run the verifier.

values.yaml must expose: image repo/tag for both, prover source value (demo only, with a comment that production reads from a real source), predicate registry contents, resource limits, and a networkPolicy.enabled flag defaulting true.

Acceptance:

helm lint helm/zk-proof-gateway passes.
helm template helm/zk-proof-gateway renders without error and the output contains a NetworkPolicy.
If a cluster is available (kind/minikube), helm install and the verifier passes against it. If no cluster, template rendering is sufficient — say so in the PR description rather than claiming it was deployed.
P3 — TERRAFORM (STRETCH, SKIP IF SHORT)

New: terraform/gke/ and terraform/eks/ Minimal modules that stand up a small cluster and install the Helm chart. Do NOT attempt Confidential Space or Nitro Enclaves in this pass — that is the follow-up paper's work, and a half-done enclave integration is worse than none.

Acceptance: terraform validate and terraform fmt -check pass. Mark clearly in the README that these are unapplied reference modules unless you have actually run them.

CROSS-CUTTING REQUIREMENTS
Do not weaken any security property. Specifically: the prover must still refuse to prove false statements; context binding including action_ref must remain intact; the gateway must remain deny-by-default; the audit chain must still verify.
No secrets in the repo. .gitignore already excludes python/keys/ and python/registry/. Generated demo keys live in volumes, never in git.
Add a CI workflow .github/workflows/ci.yml that runs tests_soundness.py and verify_e2e.py on push. Cheap, and a green badge on the README is worth real credibility to a reviewer.
Update experiments/run_all.sh only if needed; do not break the six-stage log.
PR description must state exactly what was verified by running versus what was only linted/rendered. No claims of deployment that did not happen.

## Status addendum (post-implementation)

See `CHANGELOG.md` for the PR-by-PR record and `IMPLEMENTATION_HLD.md` /
`IMPLEMENTATION_LLD.md` for full detail.

P0, P1, P2, and P3 are all done and merged to main. One deliberate
deviation from the text above, decided mid-flight with the requester, not
unilaterally: partway through P0, the prover/gateway network services were
redirected from "containerize the Python reference engine" to "the
network-facing path should be fast, not just correct." The result is a
second implementation of P0's exact HTTP contract, in Go, proving via a
Rust Bulletproofs engine (rust/zkrp, which needed a real bug fixed first --
it only proved bit-width membership, not actual cap enforcement) instead
of the Python Sigma-OR engine. python/prover_service.py and
python/agent_server.py (P0 as originally specced) both still exist,
unremoved, as the paper's E1 reference implementation; they are simply not
what P1/P2/P3 containerize and deploy. Verification latency dropped from
~500ms to single-digit milliseconds as a result.

Three follow-on passes went beyond this spec's literal scope, at the
requester's explicit ask, after P0-P3 landed:
1. Unit tests for the pieces that previously only had end-to-end coverage
   (the Rust cap-enforcement logic, the Go Schnorr-signature replication,
   the Go audit hash chain), plus a second, gateway-facing NetworkPolicy
   as defense-in-depth alongside the prover's deny-all one.
2. A real `kind` cluster run of the Helm chart, plus durable audit storage
   (a PersistentVolumeClaim in Helm instead of an `emptyDir`). This spec's
   own P2 acceptance criteria allowed "template rendering is sufficient"
   if no cluster was available, but one became available, and installing
   for real caught two genuine bugs: a Helm YAML/float-formatting trap
   that broke the prover's configured value, and an audit log that
   silently lost its entire history on every pod restart regardless of
   storage backing -- the PVC alone would have been
   necessary-but-not-sufficient without also fixing that second bug
   (corrected truncate-on-restart behavior in both the Go and Python
   audit-log implementations).
3. A dedicated security review of everything P0-P3 added (not just the
   crypto, which the soundness suite already covered): found and fixed a
   real governance-key exposure in the Docker Compose deployment (the
   secret was reachable inside the gateway container's mounted
   filesystem, contradicting this repo's own "keep the governance key off
   agent hosts" rule), two DoS-shaped gaps in the Go HTTP servers
   (unbounded request bodies, an unbounded in-memory context map), an
   information-disclosure issue (internal subprocess errors echoed into
   caller-facing JSON-RPC responses), and IAM over-scoping in the GKE
   Terraform module.

Explicitly still open, not attempted: transport authentication (mTLS)
between callers and gateway/prover -- both currently speak plain HTTP;
HTTP server timeouts and graceful shutdown on the Go services; and
set-membership/boolean-composition predicate types remain the deliberately
deferred stub the original README already called them, for the same reason
P3 skips Confidential Space/Nitro Enclaves -- a half-finished new
cryptographic construction under time pressure is worse than an honest gap.

A fourth pass, also beyond this spec's original scope, added the other
protocol binding this repo's own design docs had always described but
never implemented: A2A (Agent2Agent), alongside the existing MCP-shaped
surface, on both gateways, sharing one verification chain and ledger with
MCP. See `CHANGELOG.md`'s PR #6 entry.
