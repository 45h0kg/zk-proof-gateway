package zkctx

import "testing"

func sample() Context {
	return Context{
		RequestID:        "86369936eff7043c",
		Nonce:            "585b3227825b4ca7c487517e41c6d147",
		ActionRef:        "ord-9912",
		PredicateID:      "pretrade_notional_cap",
		PredicateVersion: 1,
		Requester:        "execution-venue",
		Prover:           "exec-agent-07",
		TS:               1787939901,
	}
}

func TestCanonical_IsDeterministic(t *testing.T) {
	a := sample().Canonical()
	b := sample().Canonical()
	if a != b {
		t.Fatalf("Canonical() must be deterministic for identical values: %q != %q", a, b)
	}
}

func TestCanonical_DiffersOnAnyFieldChange(t *testing.T) {
	base := sample().Canonical()

	withDifferentActionRef := sample()
	withDifferentActionRef.ActionRef = "ord-0000"
	if withDifferentActionRef.Canonical() == base {
		t.Fatal("changing action_ref must change the canonical binding (prevents cross-action replay)")
	}

	withDifferentNonce := sample()
	withDifferentNonce.Nonce = "00000000000000000000000000000000"
	if withDifferentNonce.Canonical() == base {
		t.Fatal("changing nonce must change the canonical binding (prevents replay)")
	}

	withDifferentVersion := sample()
	withDifferentVersion.PredicateVersion = 2
	if withDifferentVersion.Canonical() == base {
		t.Fatal("changing predicate_version must change the canonical binding (prevents cross-version replay)")
	}
}

func TestParse_RoundTripsIntoCanonical(t *testing.T) {
	c := sample()
	raw := []byte(`{"request_id":"86369936eff7043c","nonce":"585b3227825b4ca7c487517e41c6d147","action_ref":"ord-9912","predicate_id":"pretrade_notional_cap","predicate_version":1,"requester":"execution-venue","prover":"exec-agent-07","ts":1787939901}`)
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed != c {
		t.Fatalf("parsed context %+v does not equal expected %+v", parsed, c)
	}
	if parsed.Canonical() != c.Canonical() {
		t.Fatal("a context parsed from JSON must canonicalize identically to the same struct built directly")
	}
}
