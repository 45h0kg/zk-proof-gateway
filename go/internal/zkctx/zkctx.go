// Package zkctx defines the request-context object exchanged between the
// gateway's zk/context endpoint, the prover service, and back into
// tools/call -- and its canonical string form, which is what actually gets
// bound into the Rust Bulletproofs Merlin transcript (rust/zkrp's `ctx`
// argument). Binding on a canonical re-encoding of the STRUCT (fixed field
// order, fixed formatting) rather than on whatever raw bytes a client
// happened to send mirrors the Python E1 engine's approach of absorbing
// individual structured context fields rather than an opaque blob -- it
// means incidental JSON formatting differences (whitespace, key order) can
// never affect whether a proof binds to its context.
package zkctx

import (
	"encoding/json"
	"fmt"
)

type Context struct {
	RequestID        string `json:"request_id"`
	Nonce            string `json:"nonce"`
	ActionRef        string `json:"action_ref"`
	PredicateID      string `json:"predicate_id"`
	PredicateVersion int    `json:"predicate_version"`
	Requester        string `json:"requester"`
	Prover           string `json:"prover"`
	TS               int64  `json:"ts"`
}

func qstr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// Canonical renders a fixed, deterministic string for this context --
// the exact bytes absorbed into the Bulletproofs transcript at both prove
// and verify time. Field order/formatting only needs to be self-consistent
// within this package; it does not need to match Python's own context
// encoding, since the E1 (Python) and E2 (Go/Rust) engines each bind their
// own transcript independently.
func (c Context) Canonical() string {
	return fmt.Sprintf(
		`{"action_ref":%s,"nonce":%s,"predicate_id":%s,"predicate_version":%d,"prover":%s,"request_id":%s,"requester":%s,"ts":%d}`,
		qstr(c.ActionRef), qstr(c.Nonce), qstr(c.PredicateID), c.PredicateVersion,
		qstr(c.Prover), qstr(c.RequestID), qstr(c.Requester), c.TS,
	)
}

func Parse(raw []byte) (Context, error) {
	var c Context
	if err := json.Unmarshal(raw, &c); err != nil {
		return Context{}, err
	}
	return c, nil
}
