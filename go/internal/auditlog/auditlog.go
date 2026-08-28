// Package auditlog implements the append-only, hash-chained audit log,
// field-for-field and byte-for-byte compatible with zkgw.gateway.AuditLog
// (Python): entry_hash = SHA256(prev_hash || canonical(entry)), where
// canonical() matches Python's json.dumps(record, sort_keys=True) exactly
// (sorted keys, ", "/": " separators). Byte-compatibility matters because
// python/verify_e2e.py's own AuditLog.verify_chain (Python) still reads and
// re-hashes files written by this Go gateway.
package auditlog

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

type Entry struct {
	TS           int64
	RequestID    string
	Predicate    string
	Requester    string
	Prover       string
	Engine       string
	CommitmentCv string
	ProofSHA256  string
	Result       string
	VerifyMs     float64
}

type AuditLog struct {
	mu   sync.Mutex
	path string
	prev string
}

func New(path string) (*AuditLog, error) {
	f, err := os.Create(path) // truncate/create, matching Python's open(path,"w").close()
	if err != nil {
		return nil, err
	}
	f.Close()
	return &AuditLog{path: path, prev: strings.Repeat("0", 64)}, nil
}

func qstr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func ffloat(f float64) string {
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}

// canonicalBody renders the 11-field record (prev_hash included, entry_hash
// excluded) that gets hashed to produce entry_hash -- matches Python's
// json.dumps(dict(record, prev_hash=prev), sort_keys=True) at append time.
func canonicalBody(e Entry, prevHash string) string {
	return fmt.Sprintf(
		`{"commitment_Cv": %s, "engine": %s, "predicate": %s, "prev_hash": %s, "proof_sha256": %s, "prover": %s, "request_id": %s, "requester": %s, "result": %s, "ts": %d, "verify_ms": %s}`,
		qstr(e.CommitmentCv), qstr(e.Engine), qstr(e.Predicate), qstr(prevHash),
		qstr(e.ProofSHA256), qstr(e.Prover), qstr(e.RequestID), qstr(e.Requester),
		qstr(e.Result), e.TS, ffloat(e.VerifyMs),
	)
}

// canonicalFull renders the 12-field stored line (adds entry_hash) --
// matches Python's json.dumps(record, sort_keys=True) after entry_hash is
// set, which is what actually gets written to disk each line.
func canonicalFull(e Entry, prevHash, entryHash string) string {
	return fmt.Sprintf(
		`{"commitment_Cv": %s, "engine": %s, "entry_hash": %s, "predicate": %s, "prev_hash": %s, "proof_sha256": %s, "prover": %s, "request_id": %s, "requester": %s, "result": %s, "ts": %d, "verify_ms": %s}`,
		qstr(e.CommitmentCv), qstr(e.Engine), qstr(entryHash), qstr(e.Predicate), qstr(prevHash),
		qstr(e.ProofSHA256), qstr(e.Prover), qstr(e.RequestID), qstr(e.Requester),
		qstr(e.Result), e.TS, ffloat(e.VerifyMs),
	)
}

// Append writes one entry and returns its entry_hash (hex).
func (a *AuditLog) Append(e Entry) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	body := canonicalBody(e, a.prev)
	sum := sha256.Sum256([]byte(a.prev + body))
	entryHash := hex.EncodeToString(sum[:])

	line := canonicalFull(e, a.prev, entryHash) + "\n"
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		return "", err
	}
	a.prev = entryHash
	return entryHash, nil
}

// VerifyChain re-derives every entry_hash from scratch and checks the chain
// links, using the same rawRecord map -> canonical-JSON re-render approach
// as Python's AuditLog.verify_chain (round-trip through parse+re-encode, not
// a comparison of stored bytes).
func VerifyChain(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	prev := strings.Repeat("0", 64)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return false, err
		}
		claimed, _ := rec["entry_hash"].(string)
		prevHash, _ := rec["prev_hash"].(string)
		if prevHash != prev {
			return false, nil
		}
		e := Entry{
			CommitmentCv: rec["commitment_Cv"].(string),
			Engine:       rec["engine"].(string),
			Predicate:    rec["predicate"].(string),
			ProofSHA256:  rec["proof_sha256"].(string),
			Prover:       rec["prover"].(string),
			RequestID:    rec["request_id"].(string),
			Requester:    rec["requester"].(string),
			Result:       rec["result"].(string),
			TS:           int64(rec["ts"].(float64)),
			VerifyMs:     rec["verify_ms"].(float64),
		}
		body := canonicalBody(e, prevHash)
		sum := sha256.Sum256([]byte(prevHash + body))
		computed := hex.EncodeToString(sum[:])
		if computed != claimed {
			return false, nil
		}
		prev = claimed
	}
	if err := sc.Err(); err != nil {
		return false, err
	}
	return true, nil
}
