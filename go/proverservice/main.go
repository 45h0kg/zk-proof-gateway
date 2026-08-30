// Command prover-service: HTTP wrapper around the rust/zkrp Bulletproofs
// engine. Mirrors python/prover_service.py's contract exactly (same
// endpoints, same env vars, same 422-on-violation behavior) but proves via
// the Rust CLI instead of the Python Sigma-OR engine.
//
// Endpoints:
//
//	POST /prove   {"predicate": {...signed-predicate doc...}, "context": {...}}
//	              -> 200 envelope (zk-attach/v0), or
//	                 422 {"error": "predicate violated"}
//	GET  /healthz -> {"status": "ok"}
//
// Run: prover-service --port 8753 --zkrp-bin ../../rust/zkrp/target/release/zkrp
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"zkgw/internal/predicate"
	"zkgw/internal/zkctx"
	"zkgw/internal/zkrpclient"
)

const engineName = "bulletproofs-ristretto255"

// maxBodyBytes bounds request bodies well above any legitimate /prove
// request -- without a cap, decoding an attacker-controlled body of
// unbounded size is a trivial memory-exhaustion DoS.
const maxBodyBytes = 1 << 20 // 1 MiB

// readSourceValue: demo source of the private value, env var
// ZKGW_SOURCE_VALUE (cents). Production: replace with a call into a real
// OMS/position-service adapter; keep the signature (returns int64 cents,
// error) so the rest of the service does not need to change.
func readSourceValue() (int64, error) {
	v := os.Getenv("ZKGW_SOURCE_VALUE")
	if v == "" {
		return 0, fmt.Errorf("ZKGW_SOURCE_VALUE not set")
	}
	return strconv.ParseInt(v, 10, 64)
}

type proofPayload struct {
	NBits          int    `json:"nbits"`
	Cap            int64  `json:"cap"`
	ProofHex       string `json:"proof_hex"`
	CommitVHex     string `json:"commit_v_hex"`
	AttestationHex string `json:"attestation_hex,omitempty"`
}

type proveRequest struct {
	Predicate json.RawMessage `json:"predicate"`
	Context   json.RawMessage `json:"context"`
}

type envelope struct {
	Schema           string          `json:"schema"`
	PredicateID      string          `json:"predicate_id"`
	PredicateVersion int             `json:"predicate_version"`
	Engine           string          `json:"engine"`
	Context          json.RawMessage `json:"context"`
	ProofB64         string          `json:"proof_b64"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	data, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(data)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func handleProve(client *zkrpclient.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		var req proveRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("bad request: %v", err)})
			return
		}
		pred, err := predicate.ParseDoc(req.Predicate)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("bad predicate: %v", err)})
			return
		}
		if pred.PType != "range_leq" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("unsupported predicate type: %s", pred.PType)})
			return
		}
		ctx, err := zkctx.Parse(req.Context)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("bad context: %v", err)})
			return
		}
		value, err := readSourceValue()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		// Always attests (HLD.md §7): a real enclave doesn't get to opt out
		// of proving what it is on request. Whether a relying party
		// enforces the attestation is a verifier-side policy decision --
		// the gateway checks it only when governance has registered a
		// prover_measurement predicate (verifyAttachment in
		// gatewayservice), and simply ignores AttestationHex otherwise.
		res, err := client.ProveAttested(pred.Params.NBits, pred.Params.Cap, value, ctx.Canonical())
		if err != nil {
			if err == zkrpclient.ErrPredicateViolated {
				writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "predicate violated"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		payload := proofPayload{NBits: pred.Params.NBits, Cap: pred.Params.Cap,
			ProofHex: res.ProofHex, CommitVHex: res.CommitVHex, AttestationHex: res.AttestationHex}
		payloadBytes, _ := json.Marshal(payload)

		writeJSON(w, http.StatusOK, envelope{
			Schema:           "zk-attach/v0",
			PredicateID:      pred.PredicateID,
			PredicateVersion: pred.Version,
			Engine:           engineName,
			Context:          req.Context,
			ProofB64:         base64.StdEncoding.EncodeToString(payloadBytes),
		})
	}
}

// healthCheck probes this same binary's already-running instance over
// loopback and exits 0/1 -- used as the Docker HEALTHCHECK command so the
// final image needs no curl/wget.
func healthCheck(port int) {
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
	if err != nil {
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		os.Exit(1)
	}
	os.Exit(0)
}

func main() {
	host := flag.String("host", "0.0.0.0", "bind host")
	port := flag.Int("port", 8753, "bind port")
	zkrpBin := flag.String("zkrp-bin", envOr("ZKGW_ZKRP_BIN", "zkrp"), "path to the zkrp CLI binary")
	healthcheck := flag.Bool("healthcheck", false, "probe http://127.0.0.1:<port>/healthz and exit 0/1")
	flag.Parse()

	if *healthcheck {
		healthCheck(*port)
		return
	}

	client := zkrpclient.New(*zkrpBin)
	agentID := envOr("ZKGW_AGENT_ID", "exec-agent-07") // documented, not yet consumed -- see docstring above

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/prove", handleProve(client))

	addr := fmt.Sprintf("%s:%d", *host, *port)
	log.Printf("prover-service (go+rust) listening on %s (agent_id=%s, zkrp=%s)", addr, agentID, *zkrpBin)
	log.Fatal(http.ListenAndServe(addr, mux))
}
