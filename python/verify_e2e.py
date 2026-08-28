#!/usr/bin/env python3
"""End-to-end verifier for the agentic zk-attach/v0 protocol.

Boots the execution-venue server, then plays an execution agent that
holds a PRIVATE order notional and interacts purely over MCP-shaped
JSON-RPC 2.0. Exercises the positive path and four adversarial paths,
checks every expected outcome including the audit chain, and exits 0
only if all checks pass.

Scenarios:
  S1  compliant order + valid proof            -> ALLOW, order on ledger
  S2  governed call with NO attachment         -> denied (deny-by-default)
  S3  tampered proof bytes                     -> denied, audit entry FAIL
  S4  valid attachment replayed for a          -> denied (context is
      DIFFERENT order_ref                          single-use + bound)
  S5  notional above cap                       -> prover refuses locally;
                                                  nothing ever sent

Run:  python3 verify_e2e.py
"""
import base64
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
from zkgw.gateway import ExecutionAgent, AuditLog, make_envelope, Predicate  # noqa: E402
from zkgw.primitives import sign  # noqa: E402
from governance_cli import load_predicate_file, parse_predicate_doc  # noqa: E402

PORT = 8752
URL = f"http://127.0.0.1:{PORT}"
PROVER_URL = os.environ.get("ZKGW_PROVER_URL")   # unset -> in-process mode
results = []


def rpc(method, params, id_=1):
    body = json.dumps({"jsonrpc": "2.0", "id": id_, "method": method,
                       "params": params}).encode()
    req = urllib.request.Request(URL, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def obtain_envelope(pred_doc: dict, pred_obj: Predicate, ctx: dict, agent=None) -> dict:
    """Get an envelope either from the networked prover service or, in the
    default in-process mode, from the given ExecutionAgent directly. Raises
    ValueError on refusal in BOTH modes, so callers don't need to branch:
    a networked HTTP 422 (predicate violated) is translated to the same
    ValueError the in-process ExecutionAgent.prove() raises."""
    if PROVER_URL:
        body = json.dumps({"predicate": pred_doc, "context": ctx}).encode()
        req = urllib.request.Request(f"{PROVER_URL}/prove", data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 422:
                raise ValueError("predicate violated (HTTP 422 from prover service)")
            raise
    return agent.prove(pred_obj, ctx)


def check(name, ok, detail=""):
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))


def main():
    global URL

    # ZKGW_GATEWAY_URL attaches to an ALREADY-RUNNING gateway (e.g. the
    # persistent containerized stack in docker-compose.yml) instead of
    # spawning a throwaway one -- needed to exercise the real gateway's own
    # audit volume (see docker/README.md), not just re-prove the protocol
    # against a disposable instance. When set, governance bootstrap and
    # gateway spawning are both skipped; ZKGW_REGISTRY_DIR must point at
    # that gateway's registry directory (same dir also holds
    # governance.secret in the docker bootstrap, since it writes both
    # keys and the predicate into one bind-mounted directory) and
    # ZKGW_AUDIT_PATH at its audit log file.
    external_gateway = os.environ.get("ZKGW_GATEWAY_URL")
    gateway_cmd = None
    server = None
    work = None

    if external_gateway:
        URL = external_gateway
        keys = registry = pathlib.Path(os.environ["ZKGW_REGISTRY_DIR"])
        audit_path = pathlib.Path(os.environ["ZKGW_AUDIT_PATH"])
    else:
        work = pathlib.Path(tempfile.mkdtemp(prefix="zkgw_e2e_"))
        keys, registry = work / "keys", work / "registry"
        audit_path = work / "audit_log.jsonl"

        # --- governance bootstrap via the CLI (same tool a real team would use)
        subprocess.run([sys.executable, "governance_cli.py", "keygen",
                        "--out", str(keys / "governance")], cwd=HERE, check=True,
                       capture_output=True)
        subprocess.run([sys.executable, "governance_cli.py", "define",
                        "--id", "pretrade_notional_cap", "--version", "1",
                        "--type", "range_leq", "--cap", "1000000000",
                        "--nbits", "32", "--unit", "USD_cents",
                        "--owner", "risk-governance-team",
                        "--key", str(keys / "governance.secret"),
                        "--out", str(registry)], cwd=HERE, check=True,
                       capture_output=True)

        # ZKGW_GATEWAY_CMD lets this same harness drive a different gateway
        # implementation (e.g. the Go+Rust rewrite in go/gatewayservice), as
        # long as it accepts the same --port/--registry/--gov-pub/--audit flags
        # and speaks the same JSON-RPC surface. Symmetric with ZKGW_PROVER_URL
        # below: default is the in-repo Python gateway, unchanged.
        gateway_cmd = shlex.split(os.environ["ZKGW_GATEWAY_CMD"]) if os.environ.get("ZKGW_GATEWAY_CMD") \
            else [sys.executable, "agent_server.py"]
        server = subprocess.Popen(
            gateway_cmd + ["--port", str(PORT),
             "--registry", str(registry), "--gov-pub", str(keys / "governance.pub"),
             "--audit", str(audit_path)],
            cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    try:
        for _ in range(50):
            try:
                rpc("initialize", {})
                break
            except Exception:
                time.sleep(0.1)

        mode_desc = f"EXTERNAL gateway={external_gateway}" if external_gateway \
            else f"gateway={' '.join(gateway_cmd)}"
        print(f"mode: {'NETWORKED (prover=' + PROVER_URL + ')' if PROVER_URL else 'IN-PROCESS'}  {mode_desc}")

        pred_path = registry / "pretrade_notional_cap.v1.json"
        pred_doc = json.loads(pred_path.read_text())
        pred = parse_predicate_doc(pred_doc)
        tools = rpc("tools/list", {})["result"]["tools"]
        check("tools/list declares zk requirement",
              tools[0].get("x_zk_required", {}).get("predicate_id") == "pretrade_notional_cap")

        agent = ExecutionAgent("exec-agent-07", 735_000_000)   # $7.35M, private

        # ---- S1: compliant order, valid proof
        print("S1  compliant order with valid proof")
        ctx = rpc("zk/context", {"predicate_id": "pretrade_notional_cap",
                                 "predicate_version": 1, "prover": agent.agent_id,
                                 "action_ref": "ord-9912"})["result"]["context"]
        env = obtain_envelope(pred_doc, pred, ctx, agent)
        env.pop("_prove_ms", None)
        r = rpc("tools/call", {"name": "submit_order",
                               "arguments": {"order_ref": "ord-9912",
                                             "symbol": "XYZ", "side": "buy"},
                               "zk_attachment": env})
        check("ALLOW decision", r.get("result", {}).get("decision") == "ALLOW",
              f"verify {r.get('result', {}).get('verify_ms')} ms")
        wire = json.dumps(r)
        check("notional absent from every wire byte", "735000000" not in wire and "7350000" not in wire)
        ledger = rpc("venue/orders", {})["result"]["orders"]
        check("order on venue ledger", any(o["order_ref"] == "ord-9912" for o in ledger))

        # ---- S2: no attachment
        print("S2  governed call without attachment")
        r = rpc("tools/call", {"name": "submit_order",
                               "arguments": {"order_ref": "ord-0001"}})
        check("denied by default", "error" in r and "deny-by-default" in r["error"]["message"])

        # ---- S3: tampered proof
        print("S3  tampered proof bytes")
        ctx3 = rpc("zk/context", {"predicate_id": "pretrade_notional_cap",
                                  "predicate_version": 1, "prover": agent.agent_id,
                                  "action_ref": "ord-3333"})["result"]["context"]
        env3 = obtain_envelope(pred_doc, pred, ctx3, agent); env3.pop("_prove_ms", None)
        obj = json.loads(base64.b64decode(env3["proof_b64"]))
        if "proof_hex" in obj:  # E2 (Go+Rust Bulletproofs): flip one hex nibble of the proof
            ph = obj["proof_hex"]
            mid = len(ph) // 2
            flipped = format(int(ph[mid], 16) ^ 0xf, "x")
            obj["proof_hex"] = ph[:mid] + flipped + ph[mid + 1:]
        else:  # E1 (Python Sigma-OR): flip one response scalar
            obj["Pv"][0]["z0"] = hex(int(obj["Pv"][0]["z0"], 16) ^ 1)   # crypto-level tamper
        env3["proof_b64"] = base64.b64encode(
            json.dumps(obj, separators=(",", ":")).encode()).decode()
        r = rpc("tools/call", {"name": "submit_order",
                               "arguments": {"order_ref": "ord-3333"},
                               "zk_attachment": env3})
        check("tampered proof denied", "error" in r, r.get("error", {}).get("message", "")[:60])

        # ---- S4: replay valid attachment against a different order
        print("S4  replay of a valid attachment for a different order")
        ctx4 = rpc("zk/context", {"predicate_id": "pretrade_notional_cap",
                                  "predicate_version": 1, "prover": agent.agent_id,
                                  "action_ref": "ord-4444"})["result"]["context"]
        env4 = obtain_envelope(pred_doc, pred, ctx4, agent); env4.pop("_prove_ms", None)
        r = rpc("tools/call", {"name": "submit_order",
                               "arguments": {"order_ref": "ord-5555"},  # mismatch
                               "zk_attachment": env4})
        check("cross-order replay denied", "error" in r and "action_ref" in r["error"]["message"])

        # ---- S5: over-cap notional
        # In-process mode: a bad agent with a bigger private value than the
        # cap. Networked mode: the prover service has ONE fixed configured
        # value (whatever ZKGW_SOURCE_VALUE it was started with) -- there is
        # no per-request value to swap in. So the axis flips: same prover,
        # a stricter properly-signed ad hoc predicate whose cap is below the
        # prover's configured value. Either way the same property is tested:
        # the honest prover must refuse to prove a false statement.
        if PROVER_URL:
            print("S5  predicate cap set below the prover's configured value")
            strict_secret = int((keys / "governance.secret").read_text().strip(), 16)
            strict_pred = Predicate(
                "pretrade_notional_cap_strict", 1, "range_leq",
                {"cap": 100_000_000, "nbits": 32, "unit": "USD_cents"},
                "risk-governance-team")
            strict_pred.signature = sign(strict_secret, strict_pred.canonical_bytes())
            strict_doc = {
                "predicate": {"predicate_id": strict_pred.predicate_id,
                              "version": strict_pred.version, "ptype": strict_pred.ptype,
                              "params": strict_pred.params, "owner": strict_pred.owner},
                "signature": {"e": hex(strict_pred.signature[0]),
                              "z": hex(strict_pred.signature[1])},
            }
            ctx5 = rpc("zk/context", {"predicate_id": "pretrade_notional_cap_strict",
                                      "predicate_version": 1, "prover": agent.agent_id,
                                      "action_ref": "ord-6666"})["result"]["context"]
            try:
                obtain_envelope(strict_doc, strict_pred, ctx5)
                check("honest prover refuses out-of-policy value", False)
            except ValueError:
                check("honest prover refuses out-of-policy value", True)
        else:
            print("S5  notional above cap ($12.5M)")
            bad = ExecutionAgent("exec-agent-13", 1_250_000_000)
            ctx5 = rpc("zk/context", {"predicate_id": "pretrade_notional_cap",
                                      "predicate_version": 1, "prover": bad.agent_id,
                                      "action_ref": "ord-6666"})["result"]["context"]
            try:
                bad.prove(pred, ctx5)
                check("honest prover refuses out-of-policy value", False)
            except ValueError:
                check("honest prover refuses out-of-policy value", True)

        # ---- audit chain: intact, and contains S1 PASS + S3 FAIL
        print("AUDIT  hash chain and recorded outcomes")
        check("audit chain verifies", AuditLog.verify_chain(str(audit_path)))
        entries = [json.loads(l) for l in open(audit_path)]
        check("S1 recorded as PASS",
              any(e["result"] == "PASS" and e["request_id"] == ctx["request_id"] for e in entries))
        check("S3 recorded as FAIL",
              any(e["result"] == "FAIL" and e["request_id"] == ctx3["request_id"] for e in entries))
        check("no notional in any audit entry",
              all("735000000" not in json.dumps(e) for e in entries))

    finally:
        if server is not None:
            server.terminate()
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)

    n_ok = sum(results)
    print(f"\nAGENTIC PROTOCOL E2E: {n_ok}/{len(results)} checks passed")
    sys.exit(0 if n_ok == len(results) else 1)


if __name__ == "__main__":
    main()
