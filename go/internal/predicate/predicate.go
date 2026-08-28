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
	var eBytes, zBytes [32]byte
	p.SigE.FillBytes(eBytes[:])
	p.SigZ.FillBytes(zBytes[:])

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
	h.Write(p.CanonicalBytes())
	digest := h.Sum(nil)

	var e2 secp256k1.ModNScalar
	e2.SetByteSlice(digest)

	return eScalar.Equals(&e2)
}
