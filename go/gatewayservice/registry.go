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
	govPub    *secp256k1.PublicKey
	store     map[string]*predicate.Predicate
	measStore map[string]*predicate.MeasurementPredicate
}

func NewRegistry(govPub *secp256k1.PublicKey) *Registry {
	return &Registry{
		govPub:    govPub,
		store:     map[string]*predicate.Predicate{},
		measStore: map[string]*predicate.MeasurementPredicate{},
	}
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

// PublishMeasurement / GetMeasurement mirror Publish/Get for
// `prover_measurement` predicates (HLD.md §7): governance data naming the
// expected prover binary measurement, signed the same way and re-verified
// on every read for the same reason -- a compromised registry file must
// not be able to smuggle in a loosened (or absent) expectation.
func (r *Registry) PublishMeasurement(p *predicate.MeasurementPredicate) error {
	if !p.VerifySignature(r.govPub) {
		return fmt.Errorf("registry: measurement predicate not signed by governance key")
	}
	r.measStore[regKey(p.PredicateID, p.Version)] = p
	return nil
}

func (r *Registry) GetMeasurement(id string, version int) (*predicate.MeasurementPredicate, error) {
	p, ok := r.measStore[regKey(id, version)]
	if !ok {
		return nil, fmt.Errorf("registry: unknown measurement predicate %s@v%d", id, version)
	}
	if !p.VerifySignature(r.govPub) {
		return nil, fmt.Errorf("registry: stored measurement predicate failed signature check")
	}
	return p, nil
}
