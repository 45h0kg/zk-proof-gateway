# Implementation LLD — Spec.md: One-Day Containerization

File-by-file, function-by-function detail for `IMPLEMENTATION_HLD.md`. Ordered
P0 → P1 → CI → P2 → P3, matching build order. Each section lists: new/changed
files, exact signatures, error/status codes, and any judgment call taken where
`Spec.md` under-specifies something (flagged inline).

---

## P0 — prover as an HTTP service

### 0.1 New file: `python/prover_service.py`

Mirrors `agent_server.py`'s shape exactly: argparse CLI, a thin
`BaseHTTPRequestHandler`, no dependencies beyond the repo's own `zkgw` package
and `governance_cli`.

```python
#!/usr/bin/env python3
"""Prover sidecar: HTTP wrapper around rangeproof.prove_range_leq.

Owns the private value; never returns it. Structured behind
read_source_value() so a real OMS/position-service adapter can replace the
env-var demo source without touching the HTTP surface.
"""
import argparse, json, os, sys, pathlib
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from zkgw import rangeproof                                    # noqa: E402
from zkgw.gateway import make_envelope, serialize_proof, Predicate  # noqa: E402
from governance_cli import parse_predicate_doc                 # noqa: E402  (see 0.2)

ENGINE = "bitor-sigma-secp256k1-py"


def read_source_value() -> int:
    """Demo source: env var ZKGW_SOURCE_VALUE (cents).

    Production: replace with a call into the real OMS/position adapter,
    keeping this function's signature (no args, returns int cents).
    """
    return int(os.environ["ZKGW_SOURCE_VALUE"])


def agent_id() -> str:
    return os.environ.get("ZKGW_AGENT_ID", "exec-agent-07")


def handle_prove(body: dict) -> tuple[int, dict]:
    pred = parse_predicate_doc(body["predicate"])
    ctx = body["context"]
    if pred.ptype != "range_leq":
        return 400, {"error": f"unsupported predicate type: {pred.ptype}"}
    try:
        proof = rangeproof.prove_range_leq(
            read_source_value(), pred.params["cap"], pred.params["nbits"], ctx)
    except ValueError:
        return 422, {"error": "predicate violated"}
    env = make_envelope(pred, serialize_proof(proof), ENGINE, ctx)
    return 200, env


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self._json(200, {"status": "ok"})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/prove":
            return self._json(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length))
            status, payload = handle_prove(body)
        except Exception as e:
            status, payload = 400, {"error": f"bad request: {e}"}
        self._json(status, payload)

    def _json(self, status, payload):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8753)
    ap.add_argument("--host", default="0.0.0.0")   # see judgment call below
    args = ap.parse_args()
    print(f"prover-service listening on {args.host}:{args.port}", flush=True)
    HTTPServer((args.host, args.port), H).serve_forever()


if __name__ == "__main__":
    main()
```

Notes:
- `agent_id()` / `ZKGW_AGENT_ID` isn't actually consumed by `handle_prove`
  today (the context already carries `prover` id, set by whoever requested
  the context). Spec asks for the env var to exist regardless — kept as a
  documented, currently-unused knob for the future OMS adapter, per the
  spec's own framing ("keep simple, configurable").
- **No governance-signature verification happens here.** The prover trusts
  the caller to hand it the predicate whose `cap`/`nbits` it should prove
  against; it has no governance public key configured (spec doesn't list one
  as an env var for this service) and doesn't need one — signature
  verification is the *gateway's* job on the way back in via `tools/call`.
  This is a deliberate scope boundary, not an oversight: proving is
  parametrized by whatever predicate the caller names; trusting that the
  cap is the *governed* cap is enforced downstream when the gateway
  re-verifies the same signed doc against its registry.
- **Judgment call:** `--host 0.0.0.0` default. `Spec.md` doesn't mention bind
  host at all; `agent_server.py` currently hardcodes `127.0.0.1`. Left
  unreachable, this breaks every container acceptance criterion in P1 (see
  HLD §3). Apply the same fix to `agent_server.py` (0.2 below).

### 0.2 Small refactor: `python/governance_cli.py`

`load_predicate_file` currently inlines dict-parsing after reading from disk.
`prover_service.py` needs the same parsing over an already-decoded dict (the
POST body), not a file path. Extract the pure part:

```python
def parse_predicate_doc(doc: dict) -> Predicate:
    p = doc["predicate"]
    pred = Predicate(p["predicate_id"], p["version"], p["ptype"], p["params"], p["owner"])
    pred.signature = (int(doc["signature"]["e"], 16), int(doc["signature"]["z"], 16))
    return pred


def load_predicate_file(path: str) -> Predicate:
    return parse_predicate_doc(json.loads(pathlib.Path(path).read_text()))
```

Zero behavior change for existing callers (`agent_server.py`, `verify_e2e.py`,
`tests_soundness.py` if any). Purely an extraction so both the file-based and
over-the-wire callers share one code path.

### 0.3 Modify: `python/agent_server.py`

Two changes, both small:

1. Add `--host` argument (default `0.0.0.0`) to the argparser, and use it in
   `HTTPServer((args.host, args.port), H)` instead of the hardcoded
   `"127.0.0.1"`. Keeps local dev (`python3 agent_server.py`) working exactly
   as before since the new default is still reachable from `localhost`.
2. Add `GET /healthz` — currently the handler class only defines `do_POST`,
   so any GET 501s. Add:

```python
def do_GET(self):
    if self.path == "/healthz":
        data = json.dumps({"status": "ok"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    else:
        self.send_response(404)
        self.end_headers()

    def log_message(self, *a):  # already exists once on the class
        pass
```
(Fold into the existing `H` class alongside `do_POST`; don't duplicate
`log_message`.)

### 0.4 Modify: `python/verify_e2e.py`

Add a module-level mode switch and one helper, touching only the
envelope-acquisition call sites (S1, S3, S4, S5). S2 is unaffected (no
envelope involved).

```python
PROVER_URL = os.environ.get("ZKGW_PROVER_URL")   # None -> in-process mode

def obtain_envelope(pred_doc: dict, pred_obj, ctx: dict, agent=None) -> dict:
    """pred_doc: the raw registry JSON dict (for the networked path).
    pred_obj:  the parsed Predicate (for the in-process path).
    Raises ValueError on refusal, in BOTH modes, so call sites don't branch."""
    if PROVER_URL:
        body = json.dumps({"predicate": pred_doc, "context": ctx}).encode()
        req = urllib.request.Request(f"{PROVER_URL}/prove", data=body,
                                      headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 422:
                raise ValueError(f"predicate violated (HTTP 422 from prover service)")
            raise
    else:
        return agent.prove(pred_obj, ctx)
```

Why raise `ValueError` for the 422 case instead of leaving it as `HTTPError`:
scenario S5's existing assertion is `except ValueError: check(..., True)`.
Translating the wire-level 422 into the same exception type at this one
boundary means **S5's test code is identical in both modes** — matching
`Spec.md`'s literal requirement ("S5... now expects HTTP 422") at the
transport layer while not forking the test's control flow. Print which HTTP
status triggered it (already threaded through in the message) so the printed
mode banner (below) can distinguish the two paths for a human reading output.

`pred_doc` needs to exist as a raw dict alongside the already-loaded `pred`
object. Since `load_predicate_file` currently only returns the parsed
`Predicate`, add one line at the top of `main()`:

```python
pred_doc = json.loads((registry / "pretrade_notional_cap.v1.json").read_text())
pred = parse_predicate_doc(pred_doc)   # replaces load_predicate_file() call
```

Call-site changes (S1, S3, S4): replace `agent.prove(pred, ctx)` with
`obtain_envelope(pred_doc, pred, ctx, agent)`.

**S5 needs a different fix**, per HLD §6 gap 4: the networked prover has one
fixed configured value (whatever `ZKGW_SOURCE_VALUE` the running
`prover_service.py` process was started with — there's no per-request value
to swap in). So "the bad agent has a bigger private value" doesn't translate.
Instead, flip the axis: keep the *same* prover (same fixed value), but prove
against a **stricter, properly-signed ephemeral predicate** whose cap is
below whatever value the prover is configured with:

```python
# --- S5: over-cap notional (in-process), or a stricter cap (networked)
print("S5  notional above cap ($12.5M)" if not PROVER_URL
      else "S5  predicate cap set below the prover's configured value")
if PROVER_URL:
    strict_secret = int((keys / "governance.secret").read_text().strip(), 16)
    strict_pred = Predicate("pretrade_notional_cap_strict", 1, "range_leq",
                             {"cap": 100_000_000, "nbits": 32, "unit": "USD_cents"},
                             "risk-governance-team")
    strict_pred.signature = sign(strict_secret, strict_pred.canonical_bytes())
    strict_doc = {"predicate": {"predicate_id": strict_pred.predicate_id,
                                 "version": strict_pred.version, "ptype": strict_pred.ptype,
                                 "params": strict_pred.params, "owner": strict_pred.owner},
                  "signature": {"e": hex(strict_pred.signature[0]), "z": hex(strict_pred.signature[1])}}
    ctx5 = rpc("zk/context", {"predicate_id": "pretrade_notional_cap_strict",
                              "predicate_version": 1, "prover": "exec-agent-07",
                              "action_ref": "ord-6666"})["result"]["context"]
    try:
        obtain_envelope(strict_doc, strict_pred, ctx5)
        check("honest prover refuses out-of-policy value", False)
    except ValueError:
        check("honest prover refuses out-of-policy value", True)
else:
    bad = ExecutionAgent("exec-agent-13", 1_250_000_000)
    ctx5 = rpc("zk/context", {"predicate_id": "pretrade_notional_cap",
                              "predicate_version": 1, "prover": bad.agent_id,
                              "action_ref": "ord-6666"})["result"]["context"]
    try:
        bad.prove(pred, ctx5)
        check("honest prover refuses out-of-policy value", False)
    except ValueError:
        check("honest prover refuses out-of-policy value", True)
```

This still proves the property `Spec.md` cares about ("the service must NOT
produce a proof for a false statement") under the real constraint of a
networked prover with one fixed source value. `strict_pred` doesn't need to
be published to the gateway's registry — it's only used directly against the
prover in this one check, never submitted via `tools/call`. `sign` and
`Predicate` are already importable from `zkgw.primitives` / `zkgw.gateway`
(both used elsewhere in this file already).

Print-mode requirement: add one line near the top of `main()`, after the
`PROVER_URL` check:

```python
print(f"mode: {'NETWORKED (prover=' + PROVER_URL + ')' if PROVER_URL else 'IN-PROCESS'}")
```

### 0.5 Acceptance checklist (P0)

- `python3 verify_e2e.py` → 12/12, unchanged, `PROVER_URL` unset.
- Start `python3 prover_service.py --port 8753` with `ZKGW_SOURCE_VALUE=735000000`
  in one shell; in another, `ZKGW_PROVER_URL=http://localhost:8753 python3 verify_e2e.py`
  → 12/12.
- `python3 tests_soundness.py` → 11/11, untouched (no file in P0 touches
  `rangeproof.py`, `curve.py`, or `primitives.py`).

---

## P1 — containers

### 1.1 New: `python/requirements.txt`

```
# Core library and services (zkgw/, agent_server.py, prover_service.py,
# governance_cli.py) are stdlib-only and need nothing from this file.
# bench.py is the only script that needs these.
matplotlib>=3.8
numpy>=1.26
```

### 1.2 New: `docker/Dockerfile.gateway`

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY python/ /app/python/
RUN useradd --create-home --uid 1000 app \
 && mkdir -p /registry /audit \
 && chown -R app:app /app /registry /audit
USER app
ENV ZKGW_PORT=8752 \
    ZKGW_REGISTRY=/registry \
    ZKGW_GOV_PUB=/registry/governance.pub \
    ZKGW_AUDIT=/audit/audit_log.jsonl
VOLUME ["/audit"]
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD python3 -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"ZKGW_PORT\"]}/healthz', timeout=2)" || exit 1
ENTRYPOINT ["sh", "-c", \
  "exec python3 python/agent_server.py --host 0.0.0.0 --port \"$ZKGW_PORT\" --registry \"$ZKGW_REGISTRY\" --gov-pub \"$ZKGW_GOV_PUB\" --audit \"$ZKGW_AUDIT\""]
```

No build tools, no `requirements.txt` install — the gateway image never runs
`bench.py`. Non-root via `USER app`. `HEALTHCHECK` uses the loopback address
deliberately (it runs *inside* the container's own namespace, where
`agent_server.py` is now also listening on `0.0.0.0`, so `127.0.0.1` resolves
locally regardless of the bind-all change).

### 1.3 New: `docker/Dockerfile.prover`

Same base/hardening; entrypoint runs `prover_service.py` instead:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY python/ /app/python/
RUN useradd --create-home --uid 1000 app && chown -R app:app /app
USER app
ENV ZKGW_PORT=8753 ZKGW_SOURCE_VALUE=735000000 ZKGW_AGENT_ID=exec-agent-07
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD python3 -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"ZKGW_PORT\"]}/healthz', timeout=2)" || exit 1
ENTRYPOINT ["sh", "-c", \
  "exec python3 python/prover_service.py --host 0.0.0.0 --port \"$ZKGW_PORT\""]
```

`ZKGW_SOURCE_VALUE` is set here as an image-level default so the container
runs standalone for a quick smoke test; compose overrides it explicitly per
`Spec.md` (735000000 either way, but making the override explicit in compose
documents intent).

### 1.4 New: `docker/docker-compose.yml`

```yaml
# Models the paper's trust boundary: prover and gateway share an internal-
# only network; only the gateway publishes a port to the host. There is no
# route from the host, or from the gateway, to read the prover's private
# value directly -- only the proof it produces crosses the boundary.
services:
  bootstrap:
    build: {context: .., dockerfile: docker/Dockerfile.gateway}
    entrypoint: ["sh", "-c"]
    command:
      - |
        set -e
        if [ -f /registry/pretrade_notional_cap.v1.json ]; then
          echo "bootstrap: predicate already registered, skipping"; exit 0
        fi
        python3 python/governance_cli.py keygen --out /registry/governance
        python3 python/governance_cli.py define \
          --id pretrade_notional_cap --version 1 --type range_leq \
          --cap 1000000000 --nbits 32 --unit USD_cents \
          --owner risk-governance-team \
          --key /registry/governance.secret --out /registry
    volumes:
      - ./.demo-registry:/registry
    networks: [internal]

  prover:
    build: {context: .., dockerfile: docker/Dockerfile.prover}
    environment:
      ZKGW_SOURCE_VALUE: "735000000"
      ZKGW_AGENT_ID: "exec-agent-07"
    networks: [internal]     # no ports: -- never published to host
    depends_on:
      bootstrap: {condition: service_completed_successfully}

  gateway:
    build: {context: .., dockerfile: docker/Dockerfile.gateway}
    ports: ["8752:8752"]
    volumes:
      - ./.demo-registry:/registry:ro
      - ./.demo-audit:/audit
    depends_on:
      bootstrap: {condition: service_completed_successfully}
    networks: [internal, default]

networks:
  internal:
    internal: true   # no route to the outside world for anyone on this network
```

Notes tying this back to HLD §3:
- `./.demo-registry` and `./.demo-audit` are **host bind mounts**, not named
  volumes — required for the grep acceptance check and for a human to `cat`
  the registered predicate. Add both paths to `.gitignore` (1.7).
- `bootstrap`'s idempotency check is a file existence test, per `Spec.md`
  ("skip if the predicate file already exists") — simplest correct
  implementation, no need for anything fancier.
- `prover` has no `ports:` entry at all (not even `expose`) — it is reachable
  *only* by other containers on the `internal` network, by service name
  (`http://prover:8753`), which is what the P1-level `verify_e2e.py` run
  (1.6) targets.
- `gateway` is attached to both networks so it's reachable from the host
  (`default`/bridge, for the published port) — the prover never needs to be
  on `default` at all since nothing reaches it from the host side.

### 1.5 Secret generated by `bootstrap`, not committed

`governance_cli.py keygen` writes `governance.secret` into
`./.demo-registry`, a bind-mounted host directory. This is a demo key, but it
lands on the host filesystem, so it needs `.gitignore` coverage (1.7) same as
`python/keys/`.

### 1.6 Running the verifier against the containerized stack

**Judgment call, not literally specified in `Spec.md`:** the prover is
internal-only by design, so the naive host-side command in `Spec.md`'s draft
README (`ZKGW_PROVER_URL=http://localhost:8753 python3 verify_e2e.py`) cannot
work as written — nothing on the host can reach `localhost:8753`. `Spec.md`
itself anticipates this ("Adjust to whatever actually works... # or run
inside"). The correct form: run `verify_e2e.py` as a one-off container
attached to the same `internal` network, pointed at the prover's *service
name*:

```bash
docker compose -f docker/docker-compose.yml run --rm --network docker_internal \
  -e ZKGW_PROVER_URL=http://prover:8753 \
  gateway python3 python/verify_e2e.py
```

This reuses P0's `ZKGW_PROVER_URL` mode completely unmodified — the ephemeral
container spawns its own throwaway `agent_server.py` + governance bootstrap
internally (exactly as `verify_e2e.py` already does standalone) and calls out
to the *real* containerized `prover` service over the compose network for
every envelope. It proves the containerized prover behaves correctly under
real Docker networking. It intentionally does **not** exercise the
persistent `gateway` service's own audit volume — that's a separate,
simpler check (1.8) using the published port directly.

Exact network name depends on the compose project name Docker derives from
the directory (`docker_internal` assuming project name `docker`); confirm
with `docker network ls` after `up` and adjust the README command to match
what actually works, per `Spec.md`'s instruction not to write aspirational
commands.

### 1.7 New/modified: `.gitignore`

Does not exist today despite `Spec.md` assuming it does. Create it:

```
python/keys/
python/registry/
docker/.demo-registry/
docker/.demo-audit/
__pycache__/
*.pyc
rust/zkrp/target/
```

### 1.8 New: `docker/README.md`

Commands must be exactly what was run and verified (per `Spec.md`'s
cross-cutting requirement) — draft below, **replace with the actual verified
output** once run, including the real network name from 1.6:

```bash
cd docker
docker compose up --build -d
docker compose ps                      # all three healthy (bootstrap: exited 0)

# Exercise the containerized prover + a throwaway gateway over the real
# internal network:
docker compose run --rm --network <internal-network-name> \
  -e ZKGW_PROVER_URL=http://prover:8753 \
  gateway python3 python/verify_e2e.py

# Exercise the PERSISTENT gateway container directly (published port):
curl localhost:8752 -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'

docker compose logs gateway             # shows PASS and FAIL audit entries
grep -R 735000000 docker/.demo-audit/    # expect: no output
docker compose logs gateway | grep 735000000   # expect: no output
docker compose down -v
```

The two `grep`/no-output lines are the explicit check `Spec.md` requires
("Grep the gateway logs and audit volume for 735000000 -> no hits").

### 1.9 Modify: root `README.md`

- Replace `your-registry/zkgw-prover` / `your-registry/zkgw-gateway`
  placeholders in the Kubernetes section with the images actually built here
  — `zkgw-gateway:local` / `zkgw-prover:local` (or whatever tag the Helm
  `values.yaml` in P2 ends up using; keep these two in sync).
- Add a "Run with Docker" subsection pointing at `docker/README.md`, one
  paragraph, no duplication of the command list.

### 1.10 Acceptance checklist (P1)

- `docker compose up --build -d` → all healthy.
- The command from 1.6 → 12/12.
- `docker compose logs gateway` shows at least one `PASS` and one `FAIL`.
- Both greps in 1.8 → no hits.

---

## CI — `.github/workflows/ci.yml`

Cheap, run alongside P1 per HLD §7 (build order), not deferred to the end:

```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.12"}
      - name: Soundness suite
        working-directory: python
        run: python3 tests_soundness.py
      - name: Agentic protocol E2E (in-process)
        working-directory: python
        run: python3 verify_e2e.py
```

No `requirements.txt` install step — neither script imports `matplotlib`/
`numpy`; `bench.py` is deliberately out of scope for CI (it writes charts,
not pass/fail checks). Add the badge to the top of root `README.md`:
`![CI](https://github.com/<org>/<repo>/actions/workflows/ci.yml/badge.svg)`
— fill in the real org/repo slug, don't leave a placeholder.

---

## P2 — Helm chart

### 2.1 Layout

```
helm/zk-proof-gateway/
  Chart.yaml
  values.yaml
  templates/
    prover-deployment.yaml      # prover + placeholder-source sidecar pair
    gateway-deployment.yaml
    gateway-service.yaml        # ClusterIP
    registry-configmap.yaml
    networkpolicy.yaml
    NOTES.txt
```

### 2.2 `values.yaml` shape (fields `Spec.md` requires)

```yaml
prover:
  image: {repository: zkgw-prover, tag: local}
  sourceValue: 735000000   # DEMO ONLY. Production reads from a real OMS/
                           # position-service adapter behind read_source_value();
                           # never set a real notional here.
  resources: {requests: {cpu: 50m, memory: 64Mi}, limits: {cpu: 200m, memory: 128Mi}}

gateway:
  image: {repository: zkgw-gateway, tag: local}
  resources: {requests: {cpu: 50m, memory: 64Mi}, limits: {cpu: 200m, memory: 128Mi}}

registry:
  governancePub: ""          # base64 or inline PEM/hex of governance.pub
  predicates: {}             # map of filename -> signed predicate JSON contents

networkPolicy:
  enabled: true
```

### 2.3 `prover-deployment.yaml` — sidecar-with-source form

One Pod, two containers: `source` (placeholder — a busybox/sleep stand-in
representing the OMS, per `Spec.md`) and `prover` (the real image, reading
`ZKGW_SOURCE_VALUE` from `values.prover.sourceValue`, templated in as an env
var same as compose). No `Service` template for this pod at all — deny external
reachability by omission, not just by policy, since nothing needs to resolve
it by DNS name for this protocol (the calling agent isn't part of this chart;
it's the workload that owns the demo/test).

### 2.4 `networkpolicy.yaml` — reconciling `Spec.md`'s wording with the actual call graph

`Spec.md` says: "deny-by-default ingress to the governed workload; allow
only from the gateway pod selector." Read literally against this protocol,
that's backwards for the *prover* pod: the gateway never calls the prover
(the agent calls the prover directly to get an envelope, then separately
calls the gateway). If "governed workload" means the prover/source pod, the
correct policy is actually **deny all ingress, full stop** — nothing needs a
path in, not even the gateway.

Two readings, pick based on what "governed workload" is meant to protect:

- **(a)** If it means the prover/source pod (matches the paper's trust-cell
  story, matches HLD §3's diagram): `networkpolicy.yaml` denies all ingress
  to the prover pod's selector, with no `ingress:` allow-rules at all
  (empty `podSelector`, `policyTypes: [Ingress]`, no `ingress:` key = deny
  everything). Comment ties this to the paper's governed-channel assumption:
  the prover has no listener reachable except by whatever test/demo
  workload is explicitly granted, which by default is none.
- **(b)** If `Spec.md` actually means a NetworkPolicy that only lets the
  *gateway* Service be reached from within the cluster (protecting the
  gateway itself from arbitrary in-cluster callers, not the prover) — that's
  a policy on the **gateway** pod, allowing ingress only from pods matching
  some caller label, which is a different and also reasonable
  deny-by-default story ("nothing reaches the gateway except workloads
  explicitly labeled as callers").

Recommend **(a) as primary** (it's the one that maps 1:1 onto this
protocol's actual data flow and onto `HLD.md` §6/§7's threat model), and add
**(b) as a second, optional policy** if time allows, since it's also cheap
and strictly additive defense-in-depth. Flag this reconciliation explicitly
in the PR description — it's a real ambiguity in the spec text, not
something to silently pick one interpretation of.

### 2.5 Acceptance checklist (P2)

- `helm lint helm/zk-proof-gateway` passes.
- `helm template helm/zk-proof-gateway` renders without error; output
  contains a `NetworkPolicy` object (grep for `kind: NetworkPolicy`).
- If a `kind`/`minikube` cluster is available: `helm install` + a
  port-forward + a run of `verify_e2e.py` pointed at the forwarded port
  (same `ZKGW_PROVER_URL`/`ZKGW_GATEWAY_URL`-style approach as P1). If no
  cluster: template-render-only is acceptable — say so plainly in the PR
  description, per `Spec.md`'s explicit instruction not to claim deployment
  that didn't happen.

---

## P3 — Terraform (stretch, skip if short)

`terraform/gke/` and `terraform/eks/`: minimal modules, each doing (a) a
small managed cluster, (b) a `helm_release` resource pointing at the P2
chart. No Confidential Space / Nitro Enclave work — explicitly out of scope
per `Spec.md` ("a half-done enclave integration is worse than none").

Acceptance is `terraform validate` + `terraform fmt -check` in each module
directory — not an apply. Mark both modules clearly as unapplied reference
code in root `README.md` unless they are actually run against a real cloud
account, in which case say exactly what was run.

---

## Cross-cutting checklist (applies across all P-levels)

- No security property changes: prover still refuses false statements
  (P0 §0.1/§0.4), context binding untouched (no edits to `rangeproof.py`/
  `primitives.py` anywhere in this LLD), gateway stays deny-by-default
  (no new path to `submit_order` added by any P-level), audit chain
  verification (`AuditLog.verify_chain`) untouched.
- No secrets in the repo: `.gitignore` (1.7) covers both the existing
  `python/keys/`+`python/registry/` (already assumed present by `Spec.md`
  but actually missing — created here) and the two new bind-mount dirs
  under `docker/`.
- PR description must state, per file/feature, run-vs-linted-vs-rendered —
  don't let "helm template succeeded" read as "deployed to a cluster."
