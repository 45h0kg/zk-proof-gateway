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

// ------------------------------------------------- prover_measurement type
//
// Fixture generated once via a real `python3 governance_cli.py
// define-measurement` run against a throwaway keypair (see HLD.md §7 /
// CHANGELOG.md for the attestation-bound-proofs work) -- same pattern as
// fixturePredicate above: proves this package accepts a signature actually
// produced by the Python governance tooling for the new predicate type,
// not just anything this package can construct and verify against itself.
const (
	measFixturePubHex = "022452b82fd61ad8d9a934319cfc19355b696db5438af4e4ddca58095dfda75b09"
	measFixtureEHex   = "0xa3ee6b5d946b317e64c2520176607e20825dddfeb97ff76b3bf84d982653ba1"
	measFixtureZHex   = "0x39e4de653615c2df92aceec769be5aa05069bf810a36df1077964f75b74d767c"
	measFixtureHex    = "db5df15da44433d96b1df43ce82d14d5c62077cdeca0a8c2fc5247a75eb6591a92666ab300843956e1313bb8e718914b"
)

func fixtureMeasurementPredicate(t *testing.T) (*MeasurementPredicate, *secp256k1.PublicKey) {
	t.Helper()
	e, err := hexToBig(measFixtureEHex)
	if err != nil {
		t.Fatalf("hexToBig(e): %v", err)
	}
	z, err := hexToBig(measFixtureZHex)
	if err != nil {
		t.Fatalf("hexToBig(z): %v", err)
	}
	pred := &MeasurementPredicate{
		PredicateID: "prover_measurement",
		Version:     1,
		PType:       "prover_measurement",
		Params:      MeasurementParams{Algo: "sha384-mock", MeasurementHex: measFixtureHex},
		Owner:       "risk-governance-team",
		SigE:        e,
		SigZ:        z,
	}
	pubBytes, err := hex.DecodeString(measFixturePubHex)
	if err != nil {
		t.Fatalf("hex.DecodeString(pub): %v", err)
	}
	pub, err := secp256k1.ParsePubKey(pubBytes)
	if err != nil {
		t.Fatalf("ParsePubKey: %v", err)
	}
	return pred, pub
}

func TestMeasurementPredicate_VerifySignature_AcceptsRealPythonSignature(t *testing.T) {
	pred, pub := fixtureMeasurementPredicate(t)
	if !pred.VerifySignature(pub) {
		t.Fatal("expected the fixture signature (produced by Python's governance_cli.py) to verify")
	}
}

func TestMeasurementPredicate_VerifySignature_RejectsTamperedMeasurement(t *testing.T) {
	pred, pub := fixtureMeasurementPredicate(t)
	pred.Params.MeasurementHex = "00" // tamper the signed body after the fact
	if pred.VerifySignature(pub) {
		t.Fatal("signature must not verify after the measurement value changes")
	}
}

func TestMeasurementPredicate_CanonicalBytes_MatchesPythonFormat(t *testing.T) {
	pred, _ := fixtureMeasurementPredicate(t)
	got := string(pred.CanonicalBytes())
	want := `{"owner": "risk-governance-team", "params": {"algo": "sha384-mock", "measurement_hex": "` + measFixtureHex + `"}, "predicate_id": "prover_measurement", "ptype": "prover_measurement", "version": 1}`
	if got != want {
		t.Fatalf("canonical bytes mismatch:\n got:  %s\n want: %s", got, want)
	}
}

func TestPeekPType(t *testing.T) {
	doc := []byte(`{"predicate": {"ptype": "prover_measurement", "predicate_id": "x", "version": 1, "params": {}, "owner": "o"}, "signature": {"e": "0x1", "z": "0x1"}}`)
	pt, err := PeekPType(doc)
	if err != nil {
		t.Fatalf("PeekPType: %v", err)
	}
	if pt != "prover_measurement" {
		t.Fatalf("got %q, want %q", pt, "prover_measurement")
	}
}

func TestParseMeasurementDoc_RoundTrips(t *testing.T) {
	raw := []byte(`{
  "predicate": {
    "owner": "risk-governance-team",
    "params": {"algo": "sha384-mock", "measurement_hex": "` + measFixtureHex + `"},
    "predicate_id": "prover_measurement",
    "ptype": "prover_measurement",
    "version": 1
  },
  "signature": {"e": "` + measFixtureEHex + `", "z": "` + measFixtureZHex + `"}
}`)
	pred, err := ParseMeasurementDoc(raw)
	if err != nil {
		t.Fatalf("ParseMeasurementDoc: %v", err)
	}
	pubBytes, _ := hex.DecodeString(measFixturePubHex)
	pub, _ := secp256k1.ParsePubKey(pubBytes)
	if !pred.VerifySignature(pub) {
		t.Fatal("expected parsed doc's signature to verify")
	}
}
