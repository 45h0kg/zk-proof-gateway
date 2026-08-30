// Package zkrpclient wraps the rust/zkrp CLI binary (Bulletproofs range_leq
// engine) as a subprocess, so the Go services never re-implement the ZK
// math themselves -- they only shell out to the existing, tested Rust
// engine for prove/verify.
package zkrpclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
)

// ErrPredicateViolated mirrors rangeproof.prove_range_leq raising
// ValueError in the Python engine (the prover must never produce a proof
// for a false statement).
var ErrPredicateViolated = errors.New("predicate violated")

type ProveResult struct {
	ProofHex   string  `json:"proof_hex"`
	CommitVHex string  `json:"commit_v_hex"`
	ProveUs    float64 `json:"prove_us"`
	Error      string  `json:"error"`
}

type VerifyResult struct {
	OK       bool    `json:"ok"`
	VerifyUs float64 `json:"verify_us"`
}

// AttestedProveResult / AttestedVerifyResult mirror rust/zkrp's
// `attest-prove`/`attest-verify` subcommands: the attestation-bound
// predicate proof protocol proposed in HLD.md §7 (mutual binding, nonce
// unification, the mock enclave attestation) -- see attestation.rs.
type AttestedProveResult struct {
	ProofHex       string  `json:"proof_hex"`
	CommitVHex     string  `json:"commit_v_hex"`
	AttestationHex string  `json:"attestation_hex"`
	ProveUs        float64 `json:"prove_us"`
	Error          string  `json:"error"`
}

type AttestedVerifyResult struct {
	OK                   bool    `json:"ok"`
	Reason               string  `json:"reason"`
	AttestationDigestHex string  `json:"attestation_digest_hex"`
	MeasurementHex       string  `json:"measurement_hex"`
	VerifyUs             float64 `json:"verify_us"`
}

type Client struct {
	BinPath string
}

func New(binPath string) *Client {
	return &Client{BinPath: binPath}
}

func (c *Client) Prove(nbits int, cap, value int64, ctx string) (*ProveResult, error) {
	cmd := exec.Command(c.BinPath, "prove", strconv.Itoa(nbits),
		strconv.FormatInt(cap, 10), strconv.FormatInt(value, 10), ctx)
	out, runErr := cmd.Output()

	var res ProveResult
	if jsonErr := json.Unmarshal(out, &res); jsonErr != nil {
		return nil, fmt.Errorf("zkrp prove: %v (stdout=%q)", runErr, out)
	}
	if res.Error != "" {
		return nil, ErrPredicateViolated
	}
	if runErr != nil {
		return nil, fmt.Errorf("zkrp prove: unexpected failure: %w", runErr)
	}
	return &res, nil
}

func (c *Client) Verify(nbits int, cap int64, proofHex, commitVHex, ctx string) (*VerifyResult, error) {
	cmd := exec.Command(c.BinPath, "verify", strconv.Itoa(nbits),
		strconv.FormatInt(cap, 10), proofHex, commitVHex, ctx)
	out, runErr := cmd.Output()

	var res VerifyResult
	if jsonErr := json.Unmarshal(out, &res); jsonErr != nil {
		return nil, fmt.Errorf("zkrp verify: %v (stdout=%q)", runErr, out)
	}
	if runErr != nil {
		return nil, fmt.Errorf("zkrp verify: unexpected failure: %w", runErr)
	}
	return &res, nil
}

// ProveAttested calls `zkrp attest-prove`: same statement as Prove, plus a
// mock enclave attestation over the value commitment, absorbed into the
// proof's own transcript (HLD.md §7).
func (c *Client) ProveAttested(nbits int, cap, value int64, ctx string) (*AttestedProveResult, error) {
	cmd := exec.Command(c.BinPath, "attest-prove", strconv.Itoa(nbits),
		strconv.FormatInt(cap, 10), strconv.FormatInt(value, 10), ctx)
	out, runErr := cmd.Output()

	var res AttestedProveResult
	if jsonErr := json.Unmarshal(out, &res); jsonErr != nil {
		return nil, fmt.Errorf("zkrp attest-prove: %v (stdout=%q)", runErr, out)
	}
	if res.Error != "" {
		return nil, ErrPredicateViolated
	}
	if runErr != nil {
		return nil, fmt.Errorf("zkrp attest-prove: unexpected failure: %w", runErr)
	}
	return &res, nil
}

// VerifyAttested calls `zkrp attest-verify`, running the 6-step chain
// from HLD.md §7 (steps 1-5; step 6, appending to the audit log, is the
// gateway's job). expectedMeasurementHex comes from a governance-signed
// `prover_measurement` predicate -- never from the envelope itself.
func (c *Client) VerifyAttested(nbits int, cap int64, proofHex, commitVHex, ctx, attestationHex, expectedMeasurementHex string) (*AttestedVerifyResult, error) {
	cmd := exec.Command(c.BinPath, "attest-verify", strconv.Itoa(nbits),
		strconv.FormatInt(cap, 10), proofHex, commitVHex, ctx, attestationHex, expectedMeasurementHex)
	out, runErr := cmd.Output()

	var res AttestedVerifyResult
	if jsonErr := json.Unmarshal(out, &res); jsonErr != nil {
		return nil, fmt.Errorf("zkrp attest-verify: %v (stdout=%q)", runErr, out)
	}
	if runErr != nil {
		return nil, fmt.Errorf("zkrp attest-verify: unexpected failure: %w", runErr)
	}
	return &res, nil
}

// CurrentMeasurement calls `zkrp attest-measurement`: the mock enclave's
// own current PCR0 stand-in, for tooling that needs it (tests, a
// governance operator preparing a `prover_measurement` predicate) without
// duplicating the constant from attestation.rs.
func (c *Client) CurrentMeasurement() (string, error) {
	cmd := exec.Command(c.BinPath, "attest-measurement")
	out, runErr := cmd.Output()

	var res struct {
		MeasurementHex string `json:"measurement_hex"`
	}
	if jsonErr := json.Unmarshal(out, &res); jsonErr != nil {
		return "", fmt.Errorf("zkrp attest-measurement: %v (stdout=%q)", runErr, out)
	}
	if runErr != nil {
		return "", fmt.Errorf("zkrp attest-measurement: unexpected failure: %w", runErr)
	}
	return res.MeasurementHex, nil
}
