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
