package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"zkgw/internal/auditlog"
	"zkgw/internal/predicate"
	"zkgw/internal/zkctx"
	"zkgw/internal/zkrpclient"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Fixtures below were generated once via real `python3 governance_cli.py
// define` / `define-measurement` runs against a single throwaway
// governance keypair (both predicates signed by the SAME key, unlike
// predicate_test.go's two independently-generated fixtures -- a working
// Registry only has one governance pubkey, so both docs must actually
// verify under it). measFixtureHex is rust/zkrp's real
// `attest-measurement` output, so this test exercises the real mock
// enclave's actual measurement, not an arbitrary stand-in.
const (
	attGovPubHex = "0306f1926475c5e2280778d4bc8abcb1b4cdd65136c574bd5724f9f45523d3fec7"

	attRangeLeqDoc = `{
  "predicate": {
    "owner": "risk-governance-team",
    "params": {"cap": 1000000000, "nbits": 32, "unit": "USD_cents"},
    "predicate_id": "pretrade_notional_cap",
    "ptype": "range_leq",
    "version": 1
  },
  "signature": {
    "e": "0xce5eb3aa71056748bdc35da41d0b919658b6641f13c6168c199ed1cc1f5aadc3",
    "z": "0x6402b3cdb97555778db5214776dafd3e908f7f867db1752ace5f99ba14bf477b"
  }
}`

	attMeasurementDoc = `{
  "predicate": {
    "owner": "risk-governance-team",
    "params": {"algo": "sha384-mock", "measurement_hex": "db5df15da44433d96b1df43ce82d14d5c62077cdeca0a8c2fc5247a75eb6591a92666ab300843956e1313bb8e718914b"},
    "predicate_id": "prover_measurement",
    "ptype": "prover_measurement",
    "version": 1
  },
  "signature": {
    "e": "0xfa539394dac087585f61f0aeff913a8b5d05bf942ec82b4f82fe1e6d5e2e80fa",
    "z": "0xac57e144d4c1d0809410710f470f585d7673ea4fef32fd70cd9af161ed6982e"
  }
}`

	// A prover_measurement doc identical to the one above except for the
	// measurement value (a genuine, differently-signed doc from the same
	// throwaway key), so the "wrong measurement registered" test denies on
	// an actual mismatch rather than a malformed-hex/signature error.
	attWrongMeasurementDoc = `{
  "predicate": {
    "owner": "risk-governance-team",
    "params": {"algo": "sha384-mock", "measurement_hex": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
    "predicate_id": "prover_measurement",
    "ptype": "prover_measurement",
    "version": 1
  },
  "signature": {
    "e": "0x9e242916b9705c8e35aba176e563da31499fdf0c86d394d77322798bd7f299c2",
    "z": "0xe312c9c29cefa292911e4cbe5d69490a04e88e90c06d2efc722a384a3d30a83c"
  }
}`
)

func zkrpBinPathForGatewayTest(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("ZKGW_ZKRP_BIN"); p != "" {
		return p
	}
	rel := filepath.Join("..", "..", "rust", "zkrp", "target", "release", "zkrp")
	if _, err := os.Stat(rel); err != nil {
		t.Skipf("rust/zkrp release binary not built (%v); run `cargo build --release` in rust/zkrp first", err)
	}
	return rel
}

func newTestRegistry(t *testing.T, includeMeasurement bool, measurementDoc string) *Registry {
	t.Helper()
	pubBytes, err := hex.DecodeString(attGovPubHex)
	if err != nil {
		t.Fatalf("decoding gov pub: %v", err)
	}
	govPub, err := secp256k1.ParsePubKey(pubBytes)
	if err != nil {
		t.Fatalf("ParsePubKey: %v", err)
	}
	reg := NewRegistry(govPub)

	pred, err := predicate.ParseDoc([]byte(attRangeLeqDoc))
	if err != nil {
		t.Fatalf("ParseDoc: %v", err)
	}
	if err := reg.Publish(pred); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if includeMeasurement {
		measPred, err := predicate.ParseMeasurementDoc([]byte(measurementDoc))
		if err != nil {
			t.Fatalf("ParseMeasurementDoc: %v", err)
		}
		if err := reg.PublishMeasurement(measPred); err != nil {
			t.Fatalf("PublishMeasurement: %v", err)
		}
	}
	return reg
}

func newTestVenueState(t *testing.T, reg *Registry) *VenueState {
	t.Helper()
	auditPath := filepath.Join(t.TempDir(), "audit_log.jsonl")
	audit, err := auditlog.New(auditPath)
	if err != nil {
		t.Fatalf("opening audit log: %v", err)
	}
	return &VenueState{
		registry: reg,
		audit:    audit,
		zkrp:     zkrpclient.New(zkrpBinPathForGatewayTest(t)),
		contexts: map[string]*ctxEntry{},
		tasks:    map[string]*taskEntry{},
	}
}

func issueContext(state *VenueState, actionRef string) zkctx.Context {
	ctx := zkctx.Context{
		RequestID:        "req-" + actionRef,
		Nonce:            "nonce-" + actionRef,
		ActionRef:        actionRef,
		PredicateID:      "pretrade_notional_cap",
		PredicateVersion: 1,
		Requester:        "risk-agent",
		Prover:           "exec-agent-07",
		TS:               time.Now().Unix(),
	}
	state.mu.Lock()
	state.contexts[ctx.RequestID] = &ctxEntry{ctx: ctx, createdAt: time.Now()}
	state.mu.Unlock()
	return ctx
}

func buildAttestedAttachment(t *testing.T, state *VenueState, ctx zkctx.Context) json.RawMessage {
	t.Helper()
	res, err := state.zkrp.ProveAttested(32, 1_000_000_000, 735_000_000, ctx.Canonical())
	if err != nil {
		t.Fatalf("ProveAttested: %v", err)
	}
	payload := proofPayload{
		NBits: 32, Cap: 1_000_000_000,
		ProofHex: res.ProofHex, CommitVHex: res.CommitVHex, AttestationHex: res.AttestationHex,
	}
	payloadBytes, _ := json.Marshal(payload)
	ctxBytes, _ := json.Marshal(ctx)

	att := attachment{
		Schema: "zk-attach/v0", PredicateID: "pretrade_notional_cap", PredicateVersion: 1,
		Context: ctxBytes, ProofB64: base64.StdEncoding.EncodeToString(payloadBytes),
	}
	raw, _ := json.Marshal(att)
	return raw
}

func TestProcessGovernedCall_AttestedWithCorrectMeasurement_Allows(t *testing.T) {
	reg := newTestRegistry(t, true, attMeasurementDoc)
	state := newTestVenueState(t, reg)
	ctx := issueContext(state, "ord-good")
	zkAttachment := buildAttestedAttachment(t, state, ctx)

	outcome := processGovernedCall(state, "submit_order", "ord-good", zkAttachment)
	if outcome.code != 0 {
		t.Fatalf("expected ALLOW, got code=%d message=%q", outcome.code, outcome.message)
	}
}

func TestProcessGovernedCall_AttestedWithWrongMeasurement_Denies(t *testing.T) {
	reg := newTestRegistry(t, true, attWrongMeasurementDoc)
	state := newTestVenueState(t, reg)
	ctx := issueContext(state, "ord-wrongmeas")
	zkAttachment := buildAttestedAttachment(t, state, ctx)

	outcome := processGovernedCall(state, "submit_order", "ord-wrongmeas", zkAttachment)
	if outcome.code == 0 {
		t.Fatal("expected denial when the registered measurement doesn't match the prover's")
	}
}

func TestProcessGovernedCall_NoMeasurementPredicateRegistered_FallsBackButStillAllows(t *testing.T) {
	// The regression this guards against: proverservice always attests
	// (binds the attestation digest into the proof's own transcript), so
	// even when no prover_measurement predicate is registered, the
	// gateway must still verify via the ATTESTED transcript for an
	// attested envelope -- falling back to the plain (unattested)
	// transcript here would make every proof fail to verify.
	reg := newTestRegistry(t, false, "")
	state := newTestVenueState(t, reg)
	ctx := issueContext(state, "ord-nopolicy")
	zkAttachment := buildAttestedAttachment(t, state, ctx)

	outcome := processGovernedCall(state, "submit_order", "ord-nopolicy", zkAttachment)
	if outcome.code != 0 {
		t.Fatalf("expected ALLOW even without a registered measurement policy, got code=%d message=%q", outcome.code, outcome.message)
	}
}
