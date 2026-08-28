// Command gateway-service: execution-venue agent speaking MCP-shaped
// JSON-RPC 2.0 over HTTP. Rewrite of python/agent_server.py in Go, verifying
// proofs via the Rust Bulletproofs engine (rust/zkrp) instead of the Python
// Sigma-OR engine -- same protocol, same deny-by-default guarantee, same
// governance-signature scheme (predicate.VerifySignature replicates
// zkgw.primitives.sig_verify exactly, so registries signed by the existing
// governance_cli.py work unmodified).
//
// Endpoints (all via POST, JSON-RPC 2.0 body):
//
//	initialize   standard MCP-style handshake
//	tools/list   advertises tools; governed tools declare their required
//	             predicate via x_zk_required
//	zk/context   issues a fresh single-use request context
//	tools/call   the governed path: a call to a governed tool without a
//	             VALID zk_attachment is rejected and never reaches the tool
//	venue/orders inspection helper for the verifier script
//
// GET /healthz -> {"status": "ok"}
//
// Run: gateway-service --port 8752 --registry <dir> --gov-pub <path> \
//
//	--audit <path> --zkrp-bin <path to zkrp CLI>
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"zkgw/internal/auditlog"
	"zkgw/internal/predicate"
	"zkgw/internal/zkctx"
	"zkgw/internal/zkrpclient"
)

type govRequirement struct {
	PredicateID string `json:"predicate_id"`
	Version     int    `json:"version"`
}

var governedTools = map[string]govRequirement{
	"submit_order": {PredicateID: "pretrade_notional_cap", Version: 1},
}

type ctxEntry struct {
	ctx  zkctx.Context
	used bool
}

type Order struct {
	OrderRef   string `json:"order_ref"`
	Symbol     string `json:"symbol"`
	Side       string `json:"side"`
	AuditEntry string `json:"audit_entry"`
}

type VenueState struct {
	registry *Registry
	audit    *auditlog.AuditLog
	zkrp     *zkrpclient.Client

	mu       sync.Mutex
	contexts map[string]*ctxEntry
	orders   []Order
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------- JSON-RPC

type rpcRequest struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	ID     json.RawMessage `json:"id"`
}

type rpcErrorBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	Jsonrpc string        `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any           `json:"result,omitempty"`
	Error   *rpcErrorBody `json:"error,omitempty"`
}

func rpcError(id json.RawMessage, code int, message string) rpcResponse {
	return rpcResponse{Jsonrpc: "2.0", ID: id, Error: &rpcErrorBody{Code: code, Message: message}}
}

func rpcResult(id json.RawMessage, result any) rpcResponse {
	return rpcResponse{Jsonrpc: "2.0", ID: id, Result: result}
}

// ---------------------------------------------------------------- handlers

type zkContextParams struct {
	PredicateID      string `json:"predicate_id"`
	PredicateVersion int    `json:"predicate_version"`
	Prover           string `json:"prover"`
	ActionRef        string `json:"action_ref"`
}

type attachment struct {
	Schema           string          `json:"schema"`
	PredicateID      string          `json:"predicate_id"`
	PredicateVersion int             `json:"predicate_version"`
	Context          json.RawMessage `json:"context"`
	ProofB64         string          `json:"proof_b64"`
}

type toolsCallParams struct {
	Name         string          `json:"name"`
	Arguments    json.RawMessage `json:"arguments"`
	ZkAttachment json.RawMessage `json:"zk_attachment"`
}

type orderArgs struct {
	OrderRef string `json:"order_ref"`
	Symbol   string `json:"symbol"`
	Side     string `json:"side"`
}

// proofPayload mirrors proverservice's payload shape. NBits/Cap are carried
// for observability only -- the gateway NEVER trusts them for the actual
// verify call; it always uses the REGISTERED predicate's params (see
// verifyAttachment). Trusting an envelope-supplied cap would let a
// malicious prover verify against a cap of its own choosing.
type proofPayload struct {
	NBits      int    `json:"nbits"`
	Cap        int64  `json:"cap"`
	ProofHex   string `json:"proof_hex"`
	CommitVHex string `json:"commit_v_hex"`
}

func handleRPC(state *VenueState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			writeRPC(w, rpcError(nil, -32700, fmt.Sprintf("parse error: %v", err)))
			return
		}
		writeRPC(w, dispatch(state, req))
	}
}

func dispatch(state *VenueState, req rpcRequest) rpcResponse {
	switch req.Method {
	case "initialize":
		return rpcResult(req.ID, map[string]any{
			"protocolVersion": "2025-06-18",
			"serverInfo":      map[string]any{"name": "execution-venue", "version": "0.1"},
			"capabilities":    map[string]any{"tools": map[string]any{}, "experimental": map[string]any{"zk_attach": "v0"}},
		})

	case "tools/list":
		want := governedTools["submit_order"]
		return rpcResult(req.ID, map[string]any{
			"tools": []any{map[string]any{
				"name":        "submit_order",
				"description": "Submit an order for execution. Governed action.",
				"inputSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"order_ref": map[string]any{"type": "string"},
						"symbol":    map[string]any{"type": "string"},
						"side":      map[string]any{"type": "string"},
					},
					"required": []any{"order_ref"},
				},
				"x_zk_required": map[string]any{
					"predicate_id": want.PredicateID, "version": want.Version,
				},
			}},
		})

	case "zk/context":
		var p zkContextParams
		var raw map[string]json.RawMessage
		json.Unmarshal(req.Params, &raw)
		for _, k := range []string{"predicate_id", "predicate_version", "prover", "action_ref"} {
			if _, ok := raw[k]; !ok {
				return rpcError(req.ID, -32602, "missing context parameters")
			}
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return rpcError(req.ID, -32602, "missing context parameters")
		}
		ctx := zkctx.Context{
			RequestID:        randHex(8),
			Nonce:            randHex(16),
			ActionRef:        p.ActionRef,
			PredicateID:      p.PredicateID,
			PredicateVersion: p.PredicateVersion,
			Requester:        "execution-venue",
			Prover:           p.Prover,
			TS:               time.Now().Unix(),
		}
		state.mu.Lock()
		state.contexts[ctx.RequestID] = &ctxEntry{ctx: ctx}
		state.mu.Unlock()
		return rpcResult(req.ID, map[string]any{"context": ctx})

	case "tools/call":
		return handleToolsCall(state, req)

	case "venue/orders":
		state.mu.Lock()
		orders := append([]Order{}, state.orders...)
		state.mu.Unlock()
		return rpcResult(req.ID, map[string]any{"orders": orders})

	default:
		return rpcError(req.ID, -32601, fmt.Sprintf("unknown method: %s", req.Method))
	}
}

func handleToolsCall(state *VenueState, req rpcRequest) rpcResponse {
	var params toolsCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return rpcError(req.ID, -32602, "invalid params")
	}
	want, known := governedTools[params.Name]
	if !known {
		return rpcError(req.ID, -32601, fmt.Sprintf("unknown tool: %s", params.Name))
	}

	if len(params.ZkAttachment) == 0 || string(params.ZkAttachment) == "null" {
		return rpcError(req.ID, -32031, "denied: governed tool requires zk_attachment (deny-by-default)")
	}
	var attRaw map[string]json.RawMessage
	json.Unmarshal(params.ZkAttachment, &attRaw)
	for _, k := range []string{"schema", "predicate_id", "predicate_version", "context", "proof_b64"} {
		if _, ok := attRaw[k]; !ok {
			return rpcError(req.ID, -32032, fmt.Sprintf("denied: attachment missing field '%s'", k))
		}
	}
	var att attachment
	if err := json.Unmarshal(params.ZkAttachment, &att); err != nil {
		return rpcError(req.ID, -32032, fmt.Sprintf("denied: malformed attachment (%v)", err))
	}
	if att.Schema != "zk-attach/v0" {
		return rpcError(req.ID, -32032, "denied: unsupported attachment schema")
	}

	attCtx, err := zkctx.Parse(att.Context)
	if err != nil {
		return rpcError(req.ID, -32032, "denied: malformed attachment context")
	}

	state.mu.Lock()
	entry, ok := state.contexts[attCtx.RequestID]
	if !ok {
		state.mu.Unlock()
		return rpcError(req.ID, -32033, "denied: unknown request context")
	}
	if entry.used {
		state.mu.Unlock()
		return rpcError(req.ID, -32034, "denied: context already used (replay)")
	}
	if attCtx != entry.ctx {
		state.mu.Unlock()
		return rpcError(req.ID, -32035, "denied: context does not match issued context")
	}
	var args orderArgs
	json.Unmarshal(params.Arguments, &args)
	if entry.ctx.ActionRef != args.OrderRef {
		state.mu.Unlock()
		return rpcError(req.ID, -32036, "denied: attachment action_ref does not match order_ref")
	}
	entry.used = true // single use, success or failure
	state.mu.Unlock()

	if att.PredicateID != want.PredicateID || att.PredicateVersion != want.Version {
		return rpcError(req.ID, -32037, "denied: wrong predicate for this tool")
	}

	auditEntry, verifyMs, ok, err := verifyAttachment(state, att, attCtx)
	if err != nil {
		return rpcError(req.ID, -32038, fmt.Sprintf("denied: verification error (%v)", err))
	}
	if !ok {
		short := auditEntry
		if len(short) > 16 {
			short = short[:16]
		}
		return rpcError(req.ID, -32039, fmt.Sprintf("denied: proof invalid (audit %s)", short))
	}

	order := Order{OrderRef: args.OrderRef, Symbol: args.Symbol, Side: args.Side, AuditEntry: auditEntry}
	state.mu.Lock()
	state.orders = append(state.orders, order)
	state.mu.Unlock()

	return rpcResult(req.ID, map[string]any{
		"content": []any{map[string]any{"type": "text",
			"text": fmt.Sprintf("order %s ACCEPTED under %s@v%d", args.OrderRef, att.PredicateID, att.PredicateVersion)}},
		"decision":    "ALLOW",
		"audit_entry": auditEntry,
		"verify_ms":   round3(verifyMs),
	})
}

// verifyAttachment verifies the ZK proof against the REGISTERED predicate's
// params (never the envelope's own claimed cap/nbits) and appends an audit
// entry either way, mirroring zkgw.gateway.ProofGateway.verify.
func verifyAttachment(state *VenueState, att attachment, ctx zkctx.Context) (auditEntry string, verifyMs float64, ok bool, err error) {
	pred, err := state.registry.Get(att.PredicateID, att.PredicateVersion)
	if err != nil {
		return "", 0, false, err
	}
	raw, err := base64.StdEncoding.DecodeString(att.ProofB64)
	if err != nil {
		return "", 0, false, err
	}
	var payload proofPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", 0, false, err
	}

	t0 := time.Now()
	if pred.PType == "range_leq" {
		res, verr := state.zkrp.Verify(pred.Params.NBits, pred.Params.Cap, payload.ProofHex, payload.CommitVHex, ctx.Canonical())
		if verr != nil {
			return "", 0, false, verr
		}
		ok = res.OK
	}
	verifyMs = float64(time.Since(t0).Microseconds()) / 1000.0

	proofHash := sha256.Sum256(raw)
	result := "FAIL"
	if ok {
		result = "PASS"
	}
	entryHash, aerr := state.audit.Append(auditlog.Entry{
		TS:           time.Now().Unix(),
		RequestID:    ctx.RequestID,
		Predicate:    fmt.Sprintf("%s@v%d", pred.PredicateID, pred.Version),
		Requester:    ctx.Requester,
		Prover:       ctx.Prover,
		Engine:       "bulletproofs-ristretto255",
		CommitmentCv: payload.CommitVHex,
		ProofSHA256:  hex.EncodeToString(proofHash[:]),
		Result:       result,
		VerifyMs:     round3(verifyMs),
	})
	if aerr != nil {
		return "", 0, false, aerr
	}
	log.Printf("audit %s result=%s predicate=%s@v%d request_id=%s verify_ms=%.3f",
		entryHash, result, pred.PredicateID, pred.Version, ctx.RequestID, round3(verifyMs))
	return entryHash, verifyMs, ok, nil
}

func round3(f float64) float64 {
	return float64(int64(f*1000+0.5)) / 1000
}

// ---------------------------------------------------------------- plumbing

func writeRPC(w http.ResponseWriter, resp rpcResponse) {
	data, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
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
	port := flag.Int("port", 8752, "bind port")
	registryDir := flag.String("registry", "", "predicate registry directory")
	govPubPath := flag.String("gov-pub", "", "governance public key file")
	auditPath := flag.String("audit", "", "audit log path")
	zkrpBin := flag.String("zkrp-bin", envOr("ZKGW_ZKRP_BIN", "zkrp"), "path to the zkrp CLI binary")
	healthcheck := flag.Bool("healthcheck", false, "probe http://127.0.0.1:<port>/healthz and exit 0/1")
	flag.Parse()

	if *healthcheck {
		healthCheck(*port)
		return
	}

	if *registryDir == "" || *govPubPath == "" || *auditPath == "" {
		log.Fatal("--registry, --gov-pub, and --audit are required")
	}

	govPub, err := predicate.LoadGovernancePub(*govPubPath)
	if err != nil {
		log.Fatalf("loading governance pub key: %v", err)
	}
	registry := NewRegistry(govPub)

	files, err := filepath.Glob(filepath.Join(*registryDir, "*.json"))
	if err != nil {
		log.Fatalf("globbing registry dir: %v", err)
	}
	sort.Strings(files)
	for _, f := range files {
		pred, err := predicate.LoadFile(f)
		if err != nil {
			log.Fatalf("loading predicate %s: %v", f, err)
		}
		if err := registry.Publish(pred); err != nil {
			log.Fatalf("publishing predicate %s: %v", f, err)
		}
	}

	audit, err := auditlog.New(*auditPath)
	if err != nil {
		log.Fatalf("opening audit log: %v", err)
	}

	state := &VenueState{
		registry: registry,
		audit:    audit,
		zkrp:     zkrpclient.New(*zkrpBin),
		contexts: map[string]*ctxEntry{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		data, _ := json.Marshal(map[string]string{"status": "ok"})
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})
	mux.HandleFunc("/", handleRPC(state))

	addr := fmt.Sprintf("%s:%d", *host, *port)
	log.Printf("execution-venue (go+rust) listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
