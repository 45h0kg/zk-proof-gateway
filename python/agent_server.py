#!/usr/bin/env python3
"""Execution-venue agent server speaking MCP-shaped JSON-RPC 2.0 over HTTP.

Implements the paper's zk-attach/v0 protocol extension end to end:

  initialize          standard MCP-style handshake
  tools/list          advertises tools; governed tools declare which
                      predicate they require via `x_zk_required`
  zk/context          issues a fresh single-use request context (nonce,
                      request id, action reference) that the prover must
                      bind its proof to
  tools/call          the governed path. Middleware rule, deny-by-default:
                      a call to a governed tool without a VALID
                      zk_attachment is rejected with a JSON-RPC error and
                      never reaches the tool.

Verification chain on every governed call:
  1. attachment present and schema-valid
  2. context was issued by this server, is unused, and its action_ref
     matches the order in the tool arguments
  3. predicate signature re-verified against the governance public key
     (registry loaded from signed JSON files; see governance_cli.py)
  4. zero-knowledge proof verifies under the full Fiat-Shamir context
  5. result appended to the hash-chained audit log either way

Run:  python3 agent_server.py --port 8752 \
          --registry <dir> --gov-pub <path> --audit <path>
"""
import argparse
import base64
import json
import sys
import pathlib
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from zkgw.gateway import (PredicateRegistry, ProofGateway, AuditLog)  # noqa: E402
from governance_cli import load_predicate_file, _load_pub  # noqa: E402

GOVERNED_TOOLS = {
    "submit_order": {"predicate_id": "pretrade_notional_cap", "version": 1},
}


class VenueState:
    def __init__(self, registry_dir, gov_pub_path, audit_path):
        self.registry = PredicateRegistry(_load_pub(gov_pub_path))
        for f in sorted(pathlib.Path(registry_dir).glob("*.json")):
            self.registry.publish(load_predicate_file(str(f)))
        self.gateway = ProofGateway(self.registry, AuditLog(audit_path))
        self.contexts = {}        # request_id -> {"ctx": dict, "used": bool}
        self.orders = []          # accepted orders ledger


def rpc_error(id_, code, message):
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def rpc_result(id_, result):
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def handle(state: VenueState, req: dict) -> dict:
    method, params, id_ = req.get("method"), req.get("params", {}), req.get("id")

    if method == "initialize":
        return rpc_result(id_, {
            "protocolVersion": "2025-06-18",
            "serverInfo": {"name": "execution-venue", "version": "0.1"},
            "capabilities": {"tools": {}, "experimental": {"zk_attach": "v0"}},
        })

    if method == "tools/list":
        return rpc_result(id_, {"tools": [{
            "name": "submit_order",
            "description": "Submit an order for execution. Governed action.",
            "inputSchema": {"type": "object",
                            "properties": {"order_ref": {"type": "string"},
                                           "symbol": {"type": "string"},
                                           "side": {"type": "string"}},
                            "required": ["order_ref"]},
            "x_zk_required": GOVERNED_TOOLS["submit_order"],
        }]})

    if method == "zk/context":
        need = ("predicate_id", "predicate_version", "prover", "action_ref")
        if any(k not in params for k in need):
            return rpc_error(id_, -32602, "missing context parameters")
        ctx = state.gateway.new_request_context(
            params["predicate_id"], params["predicate_version"],
            requester="execution-venue", prover=params["prover"],
            action_ref=params["action_ref"])
        state.contexts[ctx["request_id"]] = {"ctx": ctx, "used": False}
        return rpc_result(id_, {"context": ctx})

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})
        if name not in GOVERNED_TOOLS:
            return rpc_error(id_, -32601, f"unknown tool: {name}")

        att = params.get("zk_attachment")
        if not att:
            return rpc_error(id_, -32031,
                             "denied: governed tool requires zk_attachment (deny-by-default)")
        for k in ("schema", "predicate_id", "predicate_version", "context", "proof_b64"):
            if k not in att:
                return rpc_error(id_, -32032, f"denied: attachment missing field '{k}'")
        if att["schema"] != "zk-attach/v0":
            return rpc_error(id_, -32032, "denied: unsupported attachment schema")

        rid = att["context"].get("request_id")
        entry = state.contexts.get(rid)
        if entry is None:
            return rpc_error(id_, -32033, "denied: unknown request context")
        if entry["used"]:
            return rpc_error(id_, -32034, "denied: context already used (replay)")
        if att["context"] != entry["ctx"]:
            return rpc_error(id_, -32035, "denied: context does not match issued context")
        if entry["ctx"]["action_ref"] != args.get("order_ref"):
            return rpc_error(id_, -32036,
                             "denied: attachment action_ref does not match order_ref")
        entry["used"] = True  # single use, success or failure

        want = GOVERNED_TOOLS[name]
        if (att["predicate_id"], att["predicate_version"]) != (want["predicate_id"], want["version"]):
            return rpc_error(id_, -32037, "denied: wrong predicate for this tool")

        try:
            outcome = state.gateway.verify(att)
        except Exception as e:  # bad proof encoding, unknown predicate, ...
            return rpc_error(id_, -32038, f"denied: verification error ({e})")
        if not outcome["ok"]:
            return rpc_error(id_, -32039,
                             f"denied: proof invalid (audit {outcome['audit_entry'][:16]})")

        order = {"order_ref": args["order_ref"], "symbol": args.get("symbol", ""),
                 "side": args.get("side", ""), "audit_entry": outcome["audit_entry"]}
        state.orders.append(order)
        return rpc_result(id_, {
            "content": [{"type": "text",
                         "text": f"order {args['order_ref']} ACCEPTED under "
                                 f"{att['predicate_id']}@v{att['predicate_version']}"}],
            "decision": "ALLOW",
            "audit_entry": outcome["audit_entry"],
            "verify_ms": round(outcome["verify_ms"], 3),
        })

    if method == "venue/orders":       # inspection helper for the verifier script
        return rpc_result(id_, {"orders": state.orders})

    return rpc_error(id_, -32601, f"unknown method: {method}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8752)
    ap.add_argument("--registry", required=True)
    ap.add_argument("--gov-pub", required=True)
    ap.add_argument("--audit", required=True)
    args = ap.parse_args()
    state = VenueState(args.registry, args.gov_pub, args.audit)

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            try:
                resp = handle(state, json.loads(body))
            except Exception as e:
                resp = rpc_error(None, -32700, f"parse error: {e}")
            data = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):  # quiet
            pass

    print(f"execution-venue listening on 127.0.0.1:{args.port}", flush=True)
    HTTPServer(("127.0.0.1", args.port), H).serve_forever()


if __name__ == "__main__":
    main()
