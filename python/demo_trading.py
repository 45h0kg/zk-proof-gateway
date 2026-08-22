"""End-to-end case study (paper Section V):

An execution agent holds a PRIVATE order notional of $7,350,000.00.
Governance has published predicate `pretrade_notional_cap` v1:
    notional_cents <= 1_000_000_000  ($10M cap, SEC 15c3-5-style pre-trade check)
The risk agent must establish compliance WITHOUT learning the notional.
"""
import json
from zkgw.primitives import rand_scalar
from zkgw.curve import G
from zkgw.gateway import (
    Predicate, PredicateRegistry, AuditLog, ProofGateway,
    ExecutionAgent, RiskAgent,
)
from zkgw.primitives import sign

SEP = "-" * 72

# --- governance bootstraps the registry -------------------------------------
gov_secret = rand_scalar()
gov_pub = gov_secret * G
registry = PredicateRegistry(gov_pub)

pred = Predicate(
    predicate_id="pretrade_notional_cap",
    version=1,
    ptype="range_leq",
    params={"cap": 1_000_000_000, "nbits": 32, "unit": "USD_cents"},
    owner="risk-governance-team",
)
pred.signature = sign(gov_secret, pred.canonical_bytes())
registry.publish(pred)

audit = AuditLog("/home/claude/zk-proof-gateway/results/audit_log.jsonl")
gateway = ProofGateway(registry, audit)

# --- agents ------------------------------------------------------------------
PRIVATE_NOTIONAL_CENTS = 735_000_000        # $7.35M, never leaves the agent
exec_agent = ExecutionAgent("exec-agent-07", PRIVATE_NOTIONAL_CENTS)
risk_agent = RiskAgent("risk-agent-01", gateway)

print(SEP)
print("SCENARIO: exec-agent-07 requests pre-trade clearance from risk-agent-01")
print(f"          private notional = $ {PRIVATE_NOTIONAL_CENTS/100:,.2f}  (cap $10,000,000.00)")
print(SEP)

result = risk_agent.check_pretrade(exec_agent, "pretrade_notional_cap", 1, action_ref="ord-9912")
env = result["envelope"]

print("WIRE MESSAGE (proof envelope attached to the tool call / handoff):")
wire_view = {k: v for k, v in env.items() if not k.startswith("_")}
wire_view["proof_b64"] = wire_view["proof_b64"][:48] + f"... ({len(env['proof_b64'])} b64 chars)"
print(json.dumps(wire_view, indent=2))
print(SEP)
print(f"DECISION: {result['decision']}   "
      f"(prove {env['_prove_ms']:.0f} ms | verify {result['verify_ms']:.0f} ms | "
      f"audit entry {result['audit_entry'][:16]}...)")
print(f"audit chain intact: {AuditLog.verify_chain(audit.path)}")
print(SEP)
print("WHAT CROSSED THE AGENT BOUNDARY: predicate id+version, request context,")
print("a Pedersen commitment, and a zero-knowledge proof.")
print("WHAT DID NOT: the notional ($7.35M), the order, any raw position data.")

# --- negative scenario: notional ABOVE cap ----------------------------------
print(SEP)
print("NEGATIVE SCENARIO: agent with notional $12.5M (> cap) tries to comply")
bad_agent = ExecutionAgent("exec-agent-13", 1_250_000_000)
try:
    risk_agent.check_pretrade(bad_agent, "pretrade_notional_cap", 1)
except ValueError as e:
    print(f"  honest prover refuses: {e}")
print("  (a MALICIOUS prover forging a proof is covered in tests_soundness.py)")
