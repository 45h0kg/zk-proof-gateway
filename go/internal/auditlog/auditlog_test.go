package auditlog

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleEntry(result string) Entry {
	return Entry{
		TS:           1787939902,
		RequestID:    "86369936eff7043c",
		Predicate:    "pretrade_notional_cap@v1",
		Requester:    "execution-venue",
		Prover:       "exec-agent-07",
		Engine:       "bulletproofs-ristretto255",
		CommitmentCv: "e6b7e9a9468e737786c7540a5050d4a82fef88831cb5de8c36e8d903c89cfe05",
		ProofSHA256:  "8093e3fd5f6bcaa7f1a65af15e040e34f42468ce6cee3728722f9ae0b481fa8f",
		Result:       result,
		VerifyMs:     4.146,
	}
}

func TestAppendAndVerifyChain_RoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	h1, err := log.Append(sampleEntry("PASS"))
	if err != nil {
		t.Fatalf("Append 1: %v", err)
	}
	h2, err := log.Append(sampleEntry("FAIL"))
	if err != nil {
		t.Fatalf("Append 2: %v", err)
	}
	if h1 == h2 {
		t.Fatal("two different entries must not produce the same hash (different prev_hash chains them)")
	}

	ok, err := VerifyChain(path)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !ok {
		t.Fatal("expected an untouched, freshly-written chain to verify")
	}
}

func TestVerifyChain_DetectsTamperedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := log.Append(sampleEntry("PASS")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := log.Append(sampleEntry("FAIL")); err != nil {
		t.Fatalf("Append: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	tampered := strings.Replace(string(raw), `"result": "PASS"`, `"result": "FAIL"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ok, err := VerifyChain(path)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if ok {
		t.Fatal("expected a tampered entry to break the hash chain")
	}
}

func TestCanonicalBody_MatchesPythonFormat(t *testing.T) {
	e := sampleEntry("PASS")
	prevHash := strings.Repeat("0", 64)
	got := canonicalBody(e, prevHash)
	want := `{"commitment_Cv": "e6b7e9a9468e737786c7540a5050d4a82fef88831cb5de8c36e8d903c89cfe05", "engine": "bulletproofs-ristretto255", "predicate": "pretrade_notional_cap@v1", "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000", "proof_sha256": "8093e3fd5f6bcaa7f1a65af15e040e34f42468ce6cee3728722f9ae0b481fa8f", "prover": "exec-agent-07", "request_id": "86369936eff7043c", "requester": "execution-venue", "result": "PASS", "ts": 1787939902, "verify_ms": 4.146}`
	if got != want {
		t.Fatalf("canonicalBody mismatch:\n got:  %s\n want: %s", got, want)
	}
}

func TestFfloat_AlwaysHasDecimalPoint(t *testing.T) {
	// Python's json.dumps always renders floats with a decimal point
	// (1.0, not 1) -- match that so cross-language re-hashing agrees.
	if got := ffloat(1.0); got != "1.0" {
		t.Fatalf("ffloat(1.0) = %q, want \"1.0\"", got)
	}
	if got := ffloat(505.932); got != "505.932" {
		t.Fatalf("ffloat(505.932) = %q, want \"505.932\"", got)
	}
}

func TestAppend_WritesOneLinePerEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := log.Append(sampleEntry("PASS")); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		n++
	}
	if n != 3 {
		t.Fatalf("expected 3 lines, got %d", n)
	}
}
