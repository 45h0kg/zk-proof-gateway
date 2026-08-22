# Canonical run results

Single logged run, all six pipeline stages green. Reproduce with
`bash experiments/run_all.sh`; full transcript in `execution_log.txt`.

Environment (as reported by the virtualized container): single-core
Intel Xeon (2.10 GHz reported), 4 GB RAM, Linux kernel 6.18 (Ubuntu
24.04), Python 3.12, rustc 1.75 (opt-level=3, lto). The host is
virtualized, so the CPU string is not a physical part number and
absolute timings vary by host. Proof sizes and all pass/fail outcomes
are host-independent.

## Bulletproofs single range proof (E2)
| bits | size  | prove   | verify  |
|------|-------|---------|---------|
| 8    | 480 B | 1.9 ms  | 0.42 ms |
| 16   | 544 B | 3.3 ms  | 0.62 ms |
| 32   | 608 B | 6.2 ms  | 1.02 ms |
| 64   | 672 B | 11.5 ms | 1.78 ms |

## Aggregation, m 64-bit statements (E2)
| m  | agg size | prove   | agg verify | m singles verify |
|----|----------|---------|------------|------------------|
| 1  | 672 B    | 12.1 ms | 1.8 ms     | 1.8 ms           |
| 16 | 928 B    | 173 ms  | 13.7 ms    | 28.5 ms          |

## Sigma bit-OR engine (E1, pedagogical)
32-bit: 28.3 KB, 749 ms prove, 766 ms verify. End-to-end (E1, in-process,
n=15): p50 1514 ms / p95 1538 ms.

## Correctness / security
- adversarial soundness suite: 11/11
- agentic protocol e2e (zk-attach/v0 over JSON-RPC): 12/12
- Rust adversarial checks: valid accepts, tampered + wrong-context reject
