package predicate

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Fixture generated once via python/governance_cli.py's underlying sign()
// (zkgw.primitives.sign) against a throwaway keypair -- proves
// VerifySignature accepts a signature actually produced by the existing
// Python governance tooling, not just anything this package itself can
// construct.
const (
	fixturePubHex = "027b8daa3698b300f6a54e95620f6f34fcc100aa2e3522d09d475ef41de0703e64"
	fixtureEHex   = "0xd1d3ab4cfa88a7aa7cae950d32858f54a915374801d5853d2f1d8ea8696ad8f2"
	fixtureZHex   = "0xf2d307cd0d801147f909d21ba63150b7089eb4fe17b1a9b970be91e275cfd3ca"
)

func fixturePredicate(t *testing.T) (*Predicate, *secp256k1.PublicKey) {
	t.Helper()
	e, err := hexToBig(fixtureEHex)
	if err != nil {
		t.Fatalf("hexToBig(e): %v", err)
	}
	z, err := hexToBig(fixtureZHex)
	if err != nil {
		t.Fatalf("hexToBig(z): %v", err)
	}
	pred := &Predicate{
		PredicateID: "pretrade_notional_cap",
		Version:     1,
		PType:       "range_leq",
		Params:      Params{Cap: 1_000_000_000, NBits: 32, Unit: "USD_cents"},
		Owner:       "risk-governance-team",
		SigE:        e,
		SigZ:        z,
	}
	pubBytes, err := hex.DecodeString(fixturePubHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(pub): %v", err)
	}
	pub, err := secp256k1.ParsePubKey(pubBytes)
	if err != nil {
		t.Fatalf("ParsePubKey: %v", err)
	}
	return pred, pub
}

func TestVerifySignature_AcceptsRealPythonSignature(t *testing.T) {
	pred, pub := fixturePredicate(t)
	if !pred.VerifySignature(pub) {
		t.Fatal("expected the fixture signature (produced by Python's governance_cli.py) to verify")
	}
}

func TestVerifySignature_RejectsWrongKey(t *testing.T) {
	pred, _ := fixturePredicate(t)
	otherSecret, _ := hexToBig("0x01")
	var buf [32]byte
	otherSecret.FillBytes(buf[:])
	var scalar secp256k1.ModNScalar
	scalar.SetByteSlice(buf[:])
	var jac secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&scalar, &jac)
	jac.ToAffine()
	wrongPub := secp256k1.NewPublicKey(&jac.X, &jac.Y)

	if pred.VerifySignature(wrongPub) {
		t.Fatal("signature must not verify against a different governance key")
	}
}

func TestVerifySignature_RejectsTamperedPredicate(t *testing.T) {
	pred, pub := fixturePredicate(t)
	pred.Params.Cap = 999_999_999 // tamper the signed body after the fact
	if pred.VerifySignature(pub) {
		t.Fatal("signature must not verify after the predicate body changes")
	}
}

func TestVerifySignature_RejectsTamperedSignature(t *testing.T) {
	pred, pub := fixturePredicate(t)
	pred.SigZ = new(big.Int).Add(pred.SigZ, big.NewInt(1)) // flip the response scalar
	if pred.VerifySignature(pub) {
		t.Fatal("tampered response scalar must not verify")
	}
}

func TestCanonicalBytes_MatchesPythonFormat(t *testing.T) {
	pred, _ := fixturePredicate(t)
	got := string(pred.CanonicalBytes())
	want := `{"owner": "risk-governance-team", "params": {"cap": 1000000000, "nbits": 32, "unit": "USD_cents"}, "predicate_id": "pretrade_notional_cap", "ptype": "range_leq", "version": 1}`
	if got != want {
		t.Fatalf("canonical bytes mismatch:\n got:  %s\n want: %s", got, want)
	}
}
