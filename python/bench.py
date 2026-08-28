"""Benchmarks for both proof engines + end-to-end gateway latency.
Outputs: results/benchmarks.csv, results/e2e_latency.csv, results/*.png
"""
import csv, json, pathlib, statistics, time
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from zkgw.curve import G
from zkgw.primitives import rand_scalar, sign
from zkgw.rangeproof import prove_range_leq, verify_range_leq
from zkgw.gateway import (Predicate, PredicateRegistry, AuditLog, ProofGateway,
                          ExecutionAgent, RiskAgent, serialize_proof)

RES = str(pathlib.Path(__file__).parent.parent / "results")
WIDTHS = [8, 16, 32, 64]
CTX = {"nonce": "bench", "request_id": "bench", "predicate_id": "p",
       "predicate_version": 1, "requester": "r", "prover": "x", "ts": 0}

# ---------------------------------------------------------------- python engine
py_rows = []
for n in WIDTHS:
    cap = (1 << n) - 1
    val = cap // 2 + 1
    pts, vts, size = [], [], 0
    iters = 6 if n >= 32 else 10
    for _ in range(iters):
        t0 = time.perf_counter()
        pf = prove_range_leq(val, cap, n, CTX)
        t1 = time.perf_counter()
        assert verify_range_leq(pf, cap, CTX)
        t2 = time.perf_counter()
        pts.append((t1 - t0) * 1e3); vts.append((t2 - t1) * 1e3)
        size = len(serialize_proof(pf))
    py_rows.append({
        "engine": "sigma-bitor-py", "nbits": n, "proof_bytes": size,
        "prove_ms_med": round(statistics.median(pts), 1),
        "verify_ms_med": round(statistics.median(vts), 1),
    })
    print(py_rows[-1])

# ---------------------------------------------------------------- rust engine
rust = json.load(open(f"{RES}/bulletproofs_bench.json"))
bp_rows = [{
    "engine": "bulletproofs-rs", "nbits": r["nbits"], "proof_bytes": r["proof_bytes"],
    "prove_ms_med": round(r["prove_us_med"] / 1000, 2),
    "verify_ms_med": round(r["verify_us_med"] / 1000, 2),
} for r in rust["single"]]

with open(f"{RES}/benchmarks.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=py_rows[0].keys())
    w.writeheader()
    for r in py_rows + bp_rows:
        w.writerow(r)

# ---------------------------------------------------------------- e2e latency
gov = rand_scalar(); reg = PredicateRegistry(gov * G)
pred = Predicate("pretrade_notional_cap", 1, "range_leq",
                 {"cap": 1_000_000_000, "nbits": 32, "unit": "USD_cents"}, "gov")
pred.signature = sign(gov, pred.canonical_bytes())
reg.publish(pred)
gw = ProofGateway(reg, AuditLog(f"{RES}/audit_bench.jsonl"))
agent = ExecutionAgent("exec", 735_000_000)
risk = RiskAgent("risk", gw)
lat = []
for _ in range(15):
    t0 = time.perf_counter()
    r = risk.check_pretrade(agent, "pretrade_notional_cap", 1)
    lat.append((time.perf_counter() - t0) * 1e3)
    assert r["decision"] == "ALLOW"
lat.sort()
e2e = {"p50_ms": round(lat[len(lat)//2], 1),
       "p95_ms": round(lat[int(len(lat)*0.95)-1], 1),
       "iters": len(lat), "engine": "sigma-bitor-py, 32-bit, in-process"}
json.dump(e2e, open(f"{RES}/e2e_latency.json", "w"), indent=1)
print("e2e:", e2e)

# ---------------------------------------------------------------- charts
def grouped(ax, rows_a, rows_b, key, title, ylab, logy=False):
    import numpy as np
    x = np.arange(len(WIDTHS)); wdt = 0.38
    ax.bar(x - wdt/2, [r[key] for r in rows_a], wdt, label="Sigma bit-OR (Python, O(n))",
           color="#c0504d")
    ax.bar(x + wdt/2, [r[key] for r in rows_b], wdt, label="Bulletproofs (Rust, O(log n))",
           color="#1f6f8b")
    ax.set_xticks(x, [f"{n}-bit" for n in WIDTHS]); ax.set_title(title)
    ax.set_ylabel(ylab)
    if logy: ax.set_yscale("log")
    ax.legend(fontsize=8); ax.grid(axis="y", alpha=0.3)

fig, axes = plt.subplots(1, 3, figsize=(13, 3.8))
grouped(axes[0], py_rows, bp_rows, "proof_bytes", "Proof size vs bit-width",
        "bytes (log)", logy=True)
grouped(axes[1], py_rows, bp_rows, "prove_ms_med", "Proof generation (median)",
        "ms (log)", logy=True)
grouped(axes[2], py_rows, bp_rows, "verify_ms_med", "Verification (median)",
        "ms (log)", logy=True)
fig.suptitle("ZK Proof Gateway range-proof engines, single vCPU Xeon 2.8 GHz", y=1.02)
fig.tight_layout()
fig.savefig(f"{RES}/engines_comparison.png", dpi=150, bbox_inches="tight")

agg = rust["aggregated_64bit"]
fig2, ax = plt.subplots(1, 2, figsize=(10, 3.6))
ms = [r["m"] for r in agg]
ax[0].plot(ms, [r["proof_bytes"] for r in agg], "o-", color="#1f6f8b",
           label="aggregated (1 proof)")
ax[0].plot(ms, [672 * m for m in ms], "s--", color="#c0504d", label="m separate proofs")
ax[0].set_xlabel("m (64-bit range statements)"); ax[0].set_ylabel("bytes")
ax[0].set_title("Aggregation: proof size"); ax[0].legend(fontsize=8); ax[0].grid(alpha=0.3)
ax[1].plot(ms, [r["verify_us_med"]/1000 for r in agg], "o-", color="#1f6f8b",
           label="aggregated verify")
ax[1].plot(ms, [2.094 * m for m in ms], "s--", color="#c0504d", label="m separate verifies")
ax[1].set_xlabel("m"); ax[1].set_ylabel("ms")
ax[1].set_title("Aggregation: verification time"); ax[1].legend(fontsize=8); ax[1].grid(alpha=0.3)
fig2.suptitle("Multi-hop composition pattern (b): aggregated proof at trust boundary")
fig2.tight_layout()
fig2.savefig(f"{RES}/aggregation.png", dpi=150, bbox_inches="tight")
print("charts written")
