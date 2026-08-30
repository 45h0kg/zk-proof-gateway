package zkrpclient

import (
	"os"
	"testing"
)

// zkrpBinPath finds the real rust/zkrp binary this package wraps. These
// tests exercise the actual subprocess contract (JSON on stdout, exit
// codes) rather than mocking it, matching how the rest of this repo
// verifies cross-language boundaries for real; they skip rather than fail
// if the binary hasn't been built (e.g. a Go-only CI job).
func zkrpBinPath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("ZKGW_ZKRP_BIN"); p != "" {
		return p
	}
	const rel = "../../../rust/zkrp/target/release/zkrp"
	if _, err := os.Stat(rel); err != nil {
		t.Skipf("rust/zkrp release binary not built (%v); run `cargo build --release` in rust/zkrp first", err)
	}
	return rel
}

func TestProveAttested_VerifyAttested_HonestRoundtrip(t *testing.T) {
	c := New(zkrpBinPath(t))
	ctx := `{"predicate_id":"pretrade_notional_cap","predicate_version":1,"nonce":"n1","action_ref":"ord-1"}`

	prove, err := c.ProveAttested(32, 1_000_000_000, 735_000_000, ctx)
	if err != nil {
		t.Fatalf("ProveAttested: %v", err)
	}
	if prove.AttestationHex == "" {
		t.Fatal("expected a non-empty attestation")
	}

	meas := currentMockMeasurementHex(t)
	verify, err := c.VerifyAttested(32, 1_000_000_000, prove.ProofHex, prove.CommitVHex, ctx, prove.AttestationHex, meas)
	if err != nil {
		t.Fatalf("VerifyAttested: %v", err)
	}
	if !verify.OK {
		t.Fatalf("expected verification to pass, reason=%q", verify.Reason)
	}
	if verify.MeasurementHex != meas {
		t.Fatalf("measurement_hex in result = %q, want %q", verify.MeasurementHex, meas)
	}
}

func TestVerifyAttested_WrongMeasurementDenied(t *testing.T) {
	c := New(zkrpBinPath(t))
	ctx := `{"predicate_id":"pretrade_notional_cap","predicate_version":1,"nonce":"n1","action_ref":"ord-1"}`

	prove, err := c.ProveAttested(32, 1_000_000_000, 735_000_000, ctx)
	if err != nil {
		t.Fatalf("ProveAttested: %v", err)
	}

	bogus := "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	verify, err := c.VerifyAttested(32, 1_000_000_000, prove.ProofHex, prove.CommitVHex, ctx, prove.AttestationHex, bogus)
	if err != nil {
		t.Fatalf("VerifyAttested: %v", err)
	}
	if verify.OK {
		t.Fatal("verification must fail against a wrong expected measurement")
	}
}

func TestVerifyAttested_ContextMismatchDenied(t *testing.T) {
	c := New(zkrpBinPath(t))
	ctxA := `{"predicate_id":"pretrade_notional_cap","predicate_version":1,"nonce":"n1","action_ref":"ord-1"}`
	ctxB := `{"predicate_id":"pretrade_notional_cap","predicate_version":1,"nonce":"n2","action_ref":"ord-1"}`

	prove, err := c.ProveAttested(32, 1_000_000_000, 735_000_000, ctxA)
	if err != nil {
		t.Fatalf("ProveAttested: %v", err)
	}
	meas := currentMockMeasurementHex(t)
	verify, err := c.VerifyAttested(32, 1_000_000_000, prove.ProofHex, prove.CommitVHex, ctxB, prove.AttestationHex, meas)
	if err != nil {
		t.Fatalf("VerifyAttested: %v", err)
	}
	if verify.OK {
		t.Fatal("verification must fail when the context at verify time differs from prove time")
	}
}

func TestProveAttested_OverCapRefusesToProve(t *testing.T) {
	c := New(zkrpBinPath(t))
	ctx := `{"predicate_id":"pretrade_notional_cap","predicate_version":1,"nonce":"n1","action_ref":"ord-1"}`
	if _, err := c.ProveAttested(32, 1_000_000_000, 5_000_000_000, ctx); err != ErrPredicateViolated {
		t.Fatalf("got err=%v, want ErrPredicateViolated", err)
	}
}

func currentMockMeasurementHex(t *testing.T) string {
	t.Helper()
	c := New(zkrpBinPath(t))
	out, err := c.CurrentMeasurement()
	if err != nil {
		t.Fatalf("attest-measurement: %v", err)
	}
	return out
}
