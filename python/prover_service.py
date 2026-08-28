#!/usr/bin/env python3
"""Prover sidecar: minimal HTTP wrapper around rangeproof.prove_range_leq.

Mirrors the style of agent_server.py: stdlib http.server, JSON over POST,
no frameworks. Owns exactly one secret -- the value behind
read_source_value() -- and never returns it; only a commitment and a proof
cross this service's boundary.

Endpoints:
  POST /prove    body {"predicate": {...signed-predicate doc...},
                        "context": {...zk/context dict...}}
                 -> 200 envelope (zk-attach/v0), or
                    422 {"error": "predicate violated"} if the private
                    value does not satisfy the predicate. This service must
                    never produce a proof for a false statement.
  GET  /healthz  -> {"status": "ok"}

Run:  python3 prover_service.py --port 8753
"""
import argparse
import json
import os
import pathlib
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from zkgw import rangeproof  # noqa: E402
from zkgw.gateway import make_envelope, serialize_proof  # noqa: E402
from governance_cli import parse_predicate_doc  # noqa: E402

ENGINE = "bitor-sigma-secp256k1-py"


def read_source_value() -> int:
    """Demo source of the private value: env var ZKGW_SOURCE_VALUE (cents).

    Production: replace this function with a call into a real OMS/
    position-service adapter. Keep the signature (no args, returns int
    cents) so the rest of the service does not need to change.
    """
    return int(os.environ["ZKGW_SOURCE_VALUE"])


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
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length))
            status, payload = handle_prove(body)
        except Exception as e:  # bad request shape, missing fields, ...
            status, payload = 400, {"error": f"bad request: {e}"}
        self._json(status, payload)

    def _json(self, status, payload):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):  # quiet
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8753)
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()
    print(f"prover-service listening on {args.host}:{args.port}", flush=True)
    HTTPServer((args.host, args.port), H).serve_forever()


if __name__ == "__main__":
    main()
