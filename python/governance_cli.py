#!/usr/bin/env python3
"""Governance CLI for the ZK Proof Gateway predicate registry.

The governing entity (risk / compliance team) uses this tool to:
  1. generate its signing keypair            -> keygen
  2. define and sign a policy predicate      -> define
  3. verify a predicate file's signature     -> verify
  4. list and check a whole registry dir     -> list

Design note: verification always takes the governance PUBLIC KEY as an
explicit argument rather than trusting a key embedded in the predicate
file. If the public key travelled inside the file, an attacker who can
swap the file could swap the key with it. The public key is the trust
anchor and must be distributed out of band (e.g., baked into the gateway
deployment).

Key storage here is demo-grade (hex file on disk). In production the
private key belongs in a KMS/HSM and signing happens in a reviewed
release pipeline, not on a laptop.

Usage examples:
  python3 governance_cli.py keygen --out keys/governance
  python3 governance_cli.py define \
      --id pretrade_notional_cap --version 1 --type range_leq \
      --cap 1000000000 --nbits 32 --unit USD_cents \
      --owner risk-governance-team \
      --key keys/governance.secret --out registry/
  python3 governance_cli.py verify --file registry/pretrade_notional_cap.v1.json \
      --pub keys/governance.pub
  python3 governance_cli.py list --dir registry --pub keys/governance.pub
"""
import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from zkgw.curve import G, Point, P, B  # noqa: E402
from zkgw.primitives import rand_scalar, sign, sig_verify  # noqa: E402
from zkgw.gateway import Predicate  # noqa: E402


def _load_pub(path: str) -> Point:
    raw = bytes.fromhex(pathlib.Path(path).read_text().strip())
    x = int.from_bytes(raw[1:], "big")
    y2 = (pow(x, 3, P) + B) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        raise ValueError("invalid public key point")
    if (y & 1) != (raw[0] & 1):
        y = P - y
    return Point(x, y)


def cmd_keygen(args):
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    secret = rand_scalar()
    pub = secret * G
    sec_path = out.with_suffix(".secret")
    pub_path = out.with_suffix(".pub")
    sec_path.write_text(hex(secret) + "\n")
    pub_path.write_text(pub.compress().hex() + "\n")
    sec_path.chmod(0o600)
    print(f"wrote {sec_path} (keep private; chmod 600 applied)")
    print(f"wrote {pub_path}  (distribute to gateways out of band)")


def cmd_define(args):
    secret = int(pathlib.Path(args.key).read_text().strip(), 16)
    pred = Predicate(
        predicate_id=args.id,
        version=args.version,
        ptype=args.type,
        params={"cap": args.cap, "nbits": args.nbits, "unit": args.unit},
        owner=args.owner,
    )
    pred.signature = sign(secret, pred.canonical_bytes())
    doc = {
        "predicate": {
            "predicate_id": pred.predicate_id,
            "version": pred.version,
            "ptype": pred.ptype,
            "params": pred.params,
            "owner": pred.owner,
        },
        "signature": {"e": hex(pred.signature[0]), "z": hex(pred.signature[1])},
    }
    outdir = pathlib.Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / f"{args.id}.v{args.version}.json"
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(f"wrote signed predicate: {path}")


def load_predicate_file(path: str) -> Predicate:
    doc = json.loads(pathlib.Path(path).read_text())
    p = doc["predicate"]
    pred = Predicate(p["predicate_id"], p["version"], p["ptype"], p["params"], p["owner"])
    pred.signature = (int(doc["signature"]["e"], 16), int(doc["signature"]["z"], 16))
    return pred


def cmd_verify(args):
    pub = _load_pub(args.pub)
    pred = load_predicate_file(args.file)
    ok = sig_verify(pub, pred.canonical_bytes(), pred.signature)
    print(f"{args.file}: signature {'VALID' if ok else 'INVALID'} "
          f"({pred.predicate_id}@v{pred.version}, {pred.ptype}, params={pred.params})")
    sys.exit(0 if ok else 1)


def cmd_list(args):
    pub = _load_pub(args.pub)
    bad = 0
    for path in sorted(pathlib.Path(args.dir).glob("*.json")):
        pred = load_predicate_file(str(path))
        ok = sig_verify(pub, pred.canonical_bytes(), pred.signature)
        bad += 0 if ok else 1
        print(f"  [{'OK ' if ok else 'BAD'}] {pred.predicate_id}@v{pred.version} "
              f"{pred.ptype} {pred.params} owner={pred.owner}")
    sys.exit(0 if bad == 0 else 1)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen"); k.add_argument("--out", required=True)
    k.set_defaults(fn=cmd_keygen)

    d = sub.add_parser("define")
    d.add_argument("--id", required=True); d.add_argument("--version", type=int, required=True)
    d.add_argument("--type", default="range_leq", choices=["range_leq"])
    d.add_argument("--cap", type=int, required=True); d.add_argument("--nbits", type=int, required=True)
    d.add_argument("--unit", default="USD_cents"); d.add_argument("--owner", required=True)
    d.add_argument("--key", required=True); d.add_argument("--out", required=True)
    d.set_defaults(fn=cmd_define)

    v = sub.add_parser("verify"); v.add_argument("--file", required=True); v.add_argument("--pub", required=True)
    v.set_defaults(fn=cmd_verify)

    l = sub.add_parser("list"); l.add_argument("--dir", required=True); l.add_argument("--pub", required=True)
    l.set_defaults(fn=cmd_list)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
