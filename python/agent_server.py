#!/usr/bin/env python3
"""Execution-venue agent server speaking two protocol surfaces over the
same JSON-RPC 2.0 HTTP endpoint: MCP-shaped methods, and A2A (Agent2Agent).

Implements the paper's zk-attach/v0 protocol extension end to end, in
either binding (see HLD.md section 5: the envelope "fits in MCP tools/call
params or an A2A message part"):

  MCP surface:
    initialize          standard MCP-style handshake
    tools/list          advertises tools; governed tools declare which
                        predicate they require via `x_zk_required`
    tools/call          the governed path

  A2A surface:
    GET /.well-known/agent.json   Agent Card (capability discovery)
    message/send                  the governed path -- a Message whose
                                   parts include a data part shaped
                                   {"skill": "submit_order", "arguments":
                                   {...}, "zk_attachment": {...}}
    tasks/get                     poll a task by id
    tasks/cancel                  always errors: every task here completes
                                   synchronously during message/send

  Shared:
    zk/context          issues a fresh single-use request context (nonce,
                        request id, action reference) that the prover must
                        bind its proof to -- used identically by callers
                        of either surface before proving
    venue/orders        inspection helper for the verifier script; the
                        orders ledger is shared across both surfaces

Verification chain on every governed call, identical regardless of which
surface invoked it (process_governed_call):
  1. attachment present and schema-valid
  2. context was issued by this server, is unused, and its action_ref
     matches the order/skill-invocation's order_ref
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
import secrets
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
        self.orders = []          # accepted orders ledger, shared MCP + A2A
        self.tasks = {}           # A2A task store: task_id -> task dict


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
        outcome = process_governed_call(state, name, args.get("order_ref"), params.get("zk_attachment"))
        if outcome["code"] != 0:
            return rpc_error(id_, outcome["code"], outcome["message"])

        order = {"order_ref": args["order_ref"], "symbol": args.get("symbol", ""),
                 "side": args.get("side", ""), "audit_entry": outcome["audit_entry"]}
        state.orders.append(order)
        return rpc_result(id_, {
            "content": [{"type": "text",
                         "text": f"order {args['order_ref']} ACCEPTED under "
                                 f"{outcome['predicate_id']}@v{outcome['predicate_version']}"}],
            "decision": "ALLOW",
            "audit_entry": outcome["audit_entry"],
            "verify_ms": round(outcome["verify_ms"], 3),
        })

    if method == "message/send":       # A2A surface, see handle_message_send
        return rpc_result(id_, handle_message_send(state, params))

    if method == "tasks/get":
        task = state.tasks.get((params or {}).get("id"))
        if task is None:
            return rpc_error(id_, -32001, "task not found")
        return rpc_result(id_, task)

    if method == "tasks/cancel":
        task = state.tasks.get((params or {}).get("id"))
        if task is None:
            return rpc_error(id_, -32001, "task not found")
        # Every task here completes synchronously during message/send
        # (proof verification is single-digit-to-low-hundreds ms) -- there
        # is never an in-flight task to actually cancel.
        return rpc_error(id_, -32002, f"task already in terminal state: {task['status']['state']}")

    if method == "venue/orders":       # inspection helper for the verifier script
        return rpc_result(id_, {"orders": state.orders})

    return rpc_error(id_, -32601, f"unknown method: {method}")


def process_governed_call(state: VenueState, tool_name, order_ref, att) -> dict:
    """Protocol-agnostic deny-by-default verification chain for a governed
    action. Both the MCP (tools/call) and A2A (message/send) handlers
    format the SAME outcome into their own wire shape, rather than
    duplicating this chain per protocol. Returns a dict with "code" == 0
    on success (plus audit_entry/verify_ms/predicate_id/predicate_version),
    or a nonzero JSON-RPC-style "code" and a "message" on denial.
    """
    want = GOVERNED_TOOLS.get(tool_name)
    if want is None:
        return {"code": -32601, "message": f"unknown tool: {tool_name}"}

    if not att:
        return {"code": -32031,
                "message": "denied: governed tool requires zk_attachment (deny-by-default)"}
    for k in ("schema", "predicate_id", "predicate_version", "context", "proof_b64"):
        if k not in att:
            return {"code": -32032, "message": f"denied: attachment missing field '{k}'"}
    if att["schema"] != "zk-attach/v0":
        return {"code": -32032, "message": "denied: unsupported attachment schema"}

    rid = att["context"].get("request_id")
    entry = state.contexts.get(rid)
    if entry is None:
        return {"code": -32033, "message": "denied: unknown request context"}
    if entry["used"]:
        return {"code": -32034, "message": "denied: context already used (replay)"}
    if att["context"] != entry["ctx"]:
        return {"code": -32035, "message": "denied: context does not match issued context"}
    if entry["ctx"]["action_ref"] != order_ref:
        return {"code": -32036, "message": "denied: attachment action_ref does not match order_ref"}
    entry["used"] = True  # single use, success or failure

    if (att["predicate_id"], att["predicate_version"]) != (want["predicate_id"], want["version"]):
        return {"code": -32037, "message": "denied: wrong predicate for this tool"}

    try:
        outcome = state.gateway.verify(att)
    except Exception as e:  # bad proof encoding, unknown predicate, ...
        return {"code": -32038, "message": f"denied: verification error ({e})"}
    if not outcome["ok"]:
        return {"code": -32039,
                "message": f"denied: proof invalid (audit {outcome['audit_entry'][:16]})"}

    return {"code": 0, "audit_entry": outcome["audit_entry"], "verify_ms": outcome["verify_ms"],
            "predicate_id": att["predicate_id"], "predicate_version": att["predicate_version"]}


# ---------------------------------------------------------------- A2A surface
#
# Same HTTP endpoint and JSON-RPC 2.0 envelope as the MCP methods above;
# only the wire shape (Message/Task instead of tools/call params/result)
# and discovery mechanism (an Agent Card instead of tools/list) differ.
# A caller: 1) calls zk/context (shared, unchanged) for a request context,
# 2) has its prover produce an envelope bound to it, 3) calls message/send
# with a Message whose parts include a data part shaped
# {"skill": "submit_order", "arguments": {...}, "zk_attachment": {...}}.

def agent_card(port: int) -> dict:
    """The A2A Agent Card, served at GET /.well-known/agent.json -- the
    wire-level analog of MCP's tools/list, but fetched over plain GET
    before any JSON-RPC call, so a caller can discover this agent without
    already knowing its method surface."""
    return {
        "name": "execution-venue",
        "description": "Execution-venue agent enforcing zk-attach/v0 governed actions -- "
                        "proves policy compliance (order notional under a pre-trade cap) "
                        "without ever exposing the underlying notional.",
        "url": f"http://localhost:{port}/",
        "version": "0.1",
        "capabilities": {"streaming": False, "pushNotifications": False, "stateTransitionHistory": False},
        "defaultInputModes": ["data"],
        "defaultOutputModes": ["data"],
        "skills": [{
            "id": "submit_order",
            "name": "Submit Order",
            "description": "Submit an order for execution. Governed: requires a zk_attachment "
                            "proof for pretrade_notional_cap@v1. Call the zk/context JSON-RPC "
                            "method first to obtain a request context to bind the proof to.",
            "tags": ["trading", "governed", "zk-attach"],
            "inputModes": ["data"],
            "outputModes": ["data"],
        }],
    }


def _a2a_task(state: str, message: dict) -> dict:
    task = {
        "id": secrets.token_hex(8),
        "contextId": secrets.token_hex(8),
        "kind": "task",
        "status": {"state": state, "message": message},
    }
    return task


def _a2a_agent_message(parts: list) -> dict:
    return {"role": "agent", "kind": "message", "messageId": secrets.token_hex(8), "parts": parts}


def handle_message_send(state: VenueState, params: dict) -> dict:
    message = (params or {}).get("message", {})
    invocation = None
    for part in message.get("parts", []):
        if part.get("kind") == "data" and isinstance(part.get("data"), dict) and part["data"].get("skill"):
            invocation = part["data"]
            break
    if invocation is None:
        task = _a2a_task("failed", _a2a_agent_message([{
            "kind": "text",
            "text": "message did not contain a data part with a skill invocation "
                    '({"skill":..., "arguments":..., "zk_attachment":...})',
        }]))
        state.tasks[task["id"]] = task
        return task

    args = invocation.get("arguments") or {}
    outcome = process_governed_call(state, invocation.get("skill"), args.get("order_ref"),
                                     invocation.get("zk_attachment"))
    if outcome["code"] != 0:
        reason = outcome["message"]
        if reason.startswith("denied: "):
            reason = reason[len("denied: "):]
        task = _a2a_task("failed", _a2a_agent_message([{"kind": "text", "text": f"denied: {reason}"}]))
        state.tasks[task["id"]] = task
        return task

    order = {"order_ref": args.get("order_ref"), "symbol": args.get("symbol", ""),
             "side": args.get("side", ""), "audit_entry": outcome["audit_entry"]}
    state.orders.append(order)

    text = (f"order {args.get('order_ref')} ACCEPTED under "
            f"{outcome['predicate_id']}@v{outcome['predicate_version']}")
    data_part = {"kind": "data", "data": {
        "decision": "ALLOW", "audit_entry": outcome["audit_entry"],
        "verify_ms": round(outcome["verify_ms"], 3),
        "predicate_id": outcome["predicate_id"], "predicate_version": outcome["predicate_version"],
    }}
    task = _a2a_task("completed", _a2a_agent_message([{"kind": "text", "text": text}, data_part]))
    state.tasks[task["id"]] = task
    return task


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8752)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--registry", required=True)
    ap.add_argument("--gov-pub", required=True)
    ap.add_argument("--audit", required=True)
    args = ap.parse_args()
    state = VenueState(args.registry, args.gov_pub, args.audit)

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/healthz":
                data = json.dumps({"status": "ok"}).encode()
            elif self.path == "/.well-known/agent.json":
                data = json.dumps(agent_card(args.port)).encode()
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

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

    print(f"execution-venue listening on {args.host}:{args.port}", flush=True)
    HTTPServer((args.host, args.port), H).serve_forever()


if __name__ == "__main__":
    main()
