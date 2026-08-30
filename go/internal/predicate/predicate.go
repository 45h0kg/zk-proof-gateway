// Package predicate parses signed predicate registry files (the same
// format governance_cli.py writes) and re-verifies their governance
// signature. VerifySignature replicates zkgw.primitives.sig_verify exactly
// (same challenge hash, same point compression, same secp256k1 curve) so
// that predicates signed by the existing Python governance_cli.py verify
// identically here -- the governance tooling does not need to change.
package predicate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Params struct {
	Cap   int64  `json:"cap"`
	NBits int    `json:"nbits"`
	Unit  string `json:"unit"`
}

type Predicate struct {
	PredicateID string
	Version     int
	PType       string
	Params      Params
	Owner       string
	SigE        *big.Int
	SigZ        *big.Int
}

type predicateJSON struct {
	PredicateID string `json:"predicate_id"`
	Version     int    `json:"version"`
	PType       string `json:"ptype"`
	Params      Params `json:"params"`
	Owner       string `json:"owner"`
}

type sigJSON struct {
	E string `json:"e"`
	Z string `json:"z"`
}

type docJSON struct {
	Predicate predicateJSON `json:"predicate"`
	Signature sigJSON       `json:"signature"`
}

func hexToBig(s string) (*big.Int, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if s == "" {
		s = "0"
	}
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return nil, fmt.Errorf("predicate: invalid hex integer %q", s)
	}
	return n, nil
}

// ParseDoc parses the same {"predicate": {...}, "signature": {"e","z"}}
// shape governance_cli.py's load_predicate_file / parse_predicate_doc read.
func ParseDoc(raw []byte) (*Predicate, error) {
	var doc docJSON
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	e, err := hexToBig(doc.Signature.E)
	if err != nil {
		return nil, err
	}
	z, err := hexToBig(doc.Signature.Z)
	if err != nil {
		return nil, err
	}
	return &Predicate{
		PredicateID: doc.Predicate.PredicateID,
		Version:     doc.Predicate.Version,
		PType:       doc.Predicate.PType,
		Params:      doc.Predicate.Params,
		Owner:       doc.Predicate.Owner,
		SigE:        e,
		SigZ:        z,
	}, nil
}

func LoadFile(path string) (*Predicate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseDoc(raw)
}

func qstr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// CanonicalBytes matches Python's
//
//	json.dumps({k:v for k,v in asdict(pred).items() if k != "signature"},
//	           sort_keys=True).encode()
//
// byte for byte: sorted top-level keys (owner, params, predicate_id, ptype,
// version), sorted nested params keys (cap, nbits, unit), default
// json.dumps separators (", " and ": ").
func (p *Predicate) CanonicalBytes() []byte {
	return []byte(fmt.Sprintf(
		`{"owner": %s, "params": {"cap": %d, "nbits": %d, "unit": %s}, "predicate_id": %s, "ptype": %s, "version": %d}`,
		qstr(p.Owner), p.Params.Cap, p.Params.NBits, qstr(p.Params.Unit),
		qstr(p.PredicateID), qstr(p.PType), p.Version,
	))
}

// LoadGovernancePub reads the hex-encoded compressed public key file
// governance_cli.py's keygen writes (governance.pub).
func LoadGovernancePub(path string) (*secp256k1.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, err
	}
	return secp256k1.ParsePubKey(b)
}

func compressAffine(x, y *secp256k1.FieldVal) []byte {
	pub := secp256k1.NewPublicKey(x, y)
	c := pub.SerializeCompressed()
	out := make([]byte, len(c))
	copy(out, c)
	return out
}

// VerifySignature replicates zkgw.primitives.sig_verify exactly:
//
//	a  = z*G - e*pub
//	e2 = SHA256(b"zkgw/sig/v1|" + compress(a) + compress(pub) + msg) mod N
//	return e == e2
func (p *Predicate) VerifySignature(govPub *secp256k1.PublicKey) bool {
	return verifySchnorr(p.CanonicalBytes(), p.SigE, p.SigZ, govPub)
}

// verifySchnorr is the shared core of every predicate type's
// VerifySignature: the Schnorr check itself doesn't depend on what's being
// signed, only on the canonical bytes each predicate type produces.
func verifySchnorr(msg []byte, e, z *big.Int, govPub *secp256k1.PublicKey) bool {
	var eBytes, zBytes [32]byte
	e.FillBytes(eBytes[:])
	z.FillBytes(zBytes[:])

	var eScalar, zScalar secp256k1.ModNScalar
	eScalar.SetByteSlice(eBytes[:])
	zScalar.SetByteSlice(zBytes[:])

	var zG secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&zScalar, &zG)

	var pubJac secp256k1.JacobianPoint
	govPub.AsJacobian(&pubJac)

	var eNeg secp256k1.ModNScalar
	eNeg.NegateVal(&eScalar)

	var negEPub secp256k1.JacobianPoint
	secp256k1.ScalarMultNonConst(&eNeg, &pubJac, &negEPub)

	var a secp256k1.JacobianPoint
	secp256k1.AddNonConst(&zG, &negEPub, &a)

	var aCompressed []byte
	a.Z.Normalize()
	if a.Z.IsZero() {
		aCompressed = make([]byte, 33) // identity: matches Point.compress()'s 33 zero bytes
	} else {
		a.ToAffine()
		aCompressed = compressAffine(&a.X, &a.Y)
	}
	pubCompressed := govPub.SerializeCompressed()

	h := sha256.New()
	h.Write([]byte("zkgw/sig/v1|"))
	h.Write(aCompressed)
	h.Write(pubCompressed)
	h.Write(msg)
	digest := h.Sum(nil)

	var e2 secp256k1.ModNScalar
	e2.SetByteSlice(digest)

	return eScalar.Equals(&e2)
}

// ------------------------------------------------------ prover_measurement
//
// Governance data naming the only prover binary measurement permitted to
// assert a cap -- signed by the same governance key, under the same
// Schnorr scheme, as a range_leq predicate (HLD.md §7). A separate Go type
// rather than a generic Params map: the fixed-format CanonicalBytes below
// must reproduce Python's json.dumps(sort_keys=True) output byte-for-byte
// for THIS field set, and range_leq's existing CanonicalBytes must not
// change to accommodate it.

type MeasurementParams struct {
	Algo           string `json:"algo"`
	MeasurementHex string `json:"measurement_hex"`
}

type MeasurementPredicate struct {
	PredicateID string
	Version     int
	PType       string
	Params      MeasurementParams
	Owner       string
	SigE        *big.Int
	SigZ        *big.Int
}

type measurementPredicateJSON struct {
	PredicateID string            `json:"predicate_id"`
	Version     int               `json:"version"`
	PType       string            `json:"ptype"`
	Params      MeasurementParams `json:"params"`
	Owner       string            `json:"owner"`
}

type measurementDocJSON struct {
	Predicate measurementPredicateJSON `json:"predicate"`
	Signature sigJSON                  `json:"signature"`
}

// PeekPType reads just the {"predicate": {"ptype": ...}} field, so a
// registry loader can dispatch to the right parser without guessing.
func PeekPType(raw []byte) (string, error) {
	var doc struct {
		Predicate struct {
			PType string `json:"ptype"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", err
	}
	return doc.Predicate.PType, nil
}

func ParseMeasurementDoc(raw []byte) (*MeasurementPredicate, error) {
	var doc measurementDocJSON
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	e, err := hexToBig(doc.Signature.E)
	if err != nil {
		return nil, err
	}
	z, err := hexToBig(doc.Signature.Z)
	if err != nil {
		return nil, err
	}
	return &MeasurementPredicate{
		PredicateID: doc.Predicate.PredicateID,
		Version:     doc.Predicate.Version,
		PType:       doc.Predicate.PType,
		Params:      doc.Predicate.Params,
		Owner:       doc.Predicate.Owner,
		SigE:        e,
		SigZ:        z,
	}, nil
}

func LoadMeasurementFile(path string) (*MeasurementPredicate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseMeasurementDoc(raw)
}

// CanonicalBytes matches Python's json.dumps({...}, sort_keys=True) for a
// prover_measurement predicate: sorted top-level keys (owner, params,
// predicate_id, ptype, version), sorted nested params keys (algo,
// measurement_hex).
func (p *MeasurementPredicate) CanonicalBytes() []byte {
	return []byte(fmt.Sprintf(
		`{"owner": %s, "params": {"algo": %s, "measurement_hex": %s}, "predicate_id": %s, "ptype": %s, "version": %d}`,
		qstr(p.Owner), qstr(p.Params.Algo), qstr(p.Params.MeasurementHex),
		qstr(p.PredicateID), qstr(p.PType), p.Version,
	))
}

func (p *MeasurementPredicate) VerifySignature(govPub *secp256k1.PublicKey) bool {
	return verifySchnorr(p.CanonicalBytes(), p.SigE, p.SigZ, govPub)
}
