package main

import (
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"zkgw/internal/predicate"
)

// Registry is governance-owned: predicates are Schnorr-signed by the
// governance key, and the signature is re-verified on every Get (not just
// at Publish time), matching zkgw.gateway.PredicateRegistry -- this is what
// prevents a compromised agent, or a tampered registry file, from smuggling
// in a loose check.
type Registry struct {
	govPub *secp256k1.PublicKey
	store  map[string]*predicate.Predicate
}

func NewRegistry(govPub *secp256k1.PublicKey) *Registry {
	return &Registry{govPub: govPub, store: map[string]*predicate.Predicate{}}
}

func regKey(id string, version int) string { return fmt.Sprintf("%s@%d", id, version) }

func (r *Registry) Publish(p *predicate.Predicate) error {
	if !p.VerifySignature(r.govPub) {
		return fmt.Errorf("registry: predicate not signed by governance key")
	}
	r.store[regKey(p.PredicateID, p.Version)] = p
	return nil
}

func (r *Registry) Get(id string, version int) (*predicate.Predicate, error) {
	p, ok := r.store[regKey(id, version)]
	if !ok {
		return nil, fmt.Errorf("registry: unknown predicate %s@v%d", id, version)
	}
	if !p.VerifySignature(r.govPub) {
		return nil, fmt.Errorf("registry: stored predicate failed signature check")
	}
	return p, nil
}
