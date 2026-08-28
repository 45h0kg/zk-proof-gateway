# Running the ZK Proof Gateway with Docker

Three containers model the paper's trust boundary: a **prover** sidecar
holding the private value (never exposed to the host), a **gateway** that
verifies proofs and enforces deny-by-default (published on `:8752`), and a
one-shot **bootstrap** job that generates the governance keypair and signs
the demo predicate. Gateway and prover are the Go+Rust stack
(`go/gatewayservice`, `go/proverservice`, `rust/zkrp`); governance predicate
signing stays Python (`governance_cli.py`), run by the bootstrap container
against a stock `python:3.12-slim` image -- it never runs inside the
gateway/prover images themselves.

Every command below has actually been run against this compose file; none
are aspirational.

## Bring the stack up

```bash
cd docker
docker compose up --build -d
docker compose ps
# NAME               PORTS                    STATUS
# docker-gateway-1   0.0.0.0:8752->8752/tcp   Up (healthy)
# docker-prover-1                             Up (healthy)   <- no PORTS: never published
```

`bootstrap` runs once, writes the governance keypair and the signed
`pretrade_notional_cap@v1` predicate into `./.demo-registry/` (a host bind
mount, not a Docker volume, so it's directly inspectable), and exits 0. It
is idempotent -- rerunning `up` skips regeneration if the predicate file
already exists.

## Run the five-scenario verifier against the real containerized stack

The prover is deliberately **not** published to the host (that's the whole
point of the trust boundary), so the verifier has to run *inside* the
`internal` compose network to reach it by service name. Find the actual
network name once (compose derives it from the directory name, so confirm
rather than assume):

```bash
docker network ls | grep internal
# e.g. docker_internal
```

Then run `verify_e2e.py` as a one-off container attached to that network,
pointed at the real `gateway` and `prover` services by their internal DNS
names (adjust the network name and the two absolute host paths to match
your checkout):

```bash
docker run --rm --network docker_internal \
  -v "$(pwd)/../python:/app:ro" \
  -v "$(pwd)/.demo-registry:/registry:ro" \
  -v "$(pwd)/.demo-audit:/audit" \
  -w /app \
  -e ZKGW_GATEWAY_URL=http://gateway:8752 \
  -e ZKGW_PROVER_URL=http://prover:8753 \
  -e ZKGW_REGISTRY_DIR=/registry \
  -e ZKGW_AUDIT_PATH=/audit/audit_log.jsonl \
  python:3.12-slim python3 verify_e2e.py
# ... AGENTIC PROTOCOL E2E: 12/12 checks passed
```

`ZKGW_GATEWAY_URL` and `ZKGW_REGISTRY_DIR`/`ZKGW_AUDIT_PATH` attach the
verifier to the **persistent** gateway container and its real registry/audit
files, instead of spawning a throwaway gateway of its own -- this is what
makes the audit-volume check below meaningful.

## Confirm the audit trail, and that the private value never crossed the boundary

```bash
docker compose logs gateway
# ... audit ... result=PASS predicate=pretrade_notional_cap@v1 ...
# ... audit ... result=FAIL predicate=pretrade_notional_cap@v1 ...

grep -c 735000000 .demo-audit/audit_log.jsonl || echo "no hits (good)"
docker compose logs gateway 2>&1 | grep -c 735000000 || echo "no hits (good)"
```

Both greps must report zero hits: the audit log and the gateway's own
container logs contain predicate ids, request contexts, commitments, and
proof hashes -- never the notional itself.

## Tear down

```bash
docker compose down -v
```

`-v` also removes the compose-managed volumes; the bind-mounted
`.demo-registry/` and `.demo-audit/` directories are host files and are left
in place (delete them by hand, e.g. `rm -rf .demo-registry .demo-audit`, if
you want a fully clean slate before the next `up`).
