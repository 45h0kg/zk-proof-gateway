"""End-to-end case study (paper Section V):

An execution agent holds a PRIVATE order notional of $7,350,000.00,
placed on behalf of a retail client -- personal data under GDPR, since it
relates to an identifiable natural person. Governance has published
predicate `pretrade_notional_cap` v1:
    notional_cents <= 1_000_000_000  ($10M cap)

Legal grounding for the case study (illustrative motivation, not a
compliance certification of this code):
  - GDPR Art. 5(1)(c) (data minimisation) + Art. 25 (data protection by
    design and by default) are the primary fit -- this is what the proof
    actually buys, architecturally, not just a policy promise: the risk
    agent establishes "policy satisfied" without the client's notional
    ever being collected or seen.
  - GDPR Art. 22 (automated individual decision-making) is a narrower,
    more careful fit: an ALLOW/DENY made without human review can fall
    within its scope where it produces legal or similarly significant
    effects on the client. Whether any given deployment crosses that
    threshold is deployment-specific and not asserted here; the
    hash-chained audit log below is designed to support the kind of
    explanation and contestability Art. 22(3) requires wherever it does
    apply.
  - The EU AI Act's record-keeping duty for high-risk AI systems
    (Art. 12) is cited for shape, not classification: this is a
    cryptographic range check, not a machine-learning system, so the
    Act's high-risk category is unlikely to reach it directly -- but a
    larger automated trading/compliance pipeline built around a check
    like this could be in scope, and this append-only audit chain is
    built to the kind of logging Art. 12 asks for.
  - MiFID II Art. 17 / RTS 6 is why a pre-trade notional cap exists at
    all: investment firms doing algorithmic trading must have real-time,
    pre-trade controls on order size. That's the business rule; GDPR is
    why proving compliance with it must not require exposing the
    client's data to do so.

The risk agent must establish compliance WITHOUT learning the notional.
"""
import json
import pathlib
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

RESULTS = pathlib.Path(__file__).parent.parent / "results"
RESULTS.mkdir(exist_ok=True)
audit = AuditLog(str(RESULTS / "audit_log.jsonl"))
gateway = ProofGateway(registry, audit)

# --- agents ------------------------------------------------------------------
PRIVATE_NOTIONAL_CENTS = 735_000_000        # $7.35M, a retail client's order notional -- never leaves the agent
exec_agent = ExecutionAgent("exec-agent-07", PRIVATE_NOTIONAL_CENTS)
risk_agent = RiskAgent("risk-agent-01", gateway)

print(SEP)
print("SCENARIO: exec-agent-07 requests pre-trade clearance from risk-agent-01")
print(f"          private notional (retail client's order) = $ {PRIVATE_NOTIONAL_CENTS/100:,.2f}  (cap $10,000,000.00)")
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
