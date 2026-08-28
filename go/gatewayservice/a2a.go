// A2A (Agent2Agent) protocol surface, alongside the existing MCP-shaped
// JSON-RPC methods in main.go. Same HTTP endpoint, same JSON-RPC 2.0
// envelope, same VenueState and processGovernedCall verification chain --
// only the wire shape (Message/Task instead of tools/call params/result)
// and the discovery mechanism (an Agent Card instead of tools/list)
// differ. This is the other half of the binding HLD.md's zk-attach/v0
// section already described ("fits in MCP tools/call params or an A2A
// message part") but never implemented.
//
// A2A methods: message/send, tasks/get, tasks/cancel.
// Discovery:   GET /.well-known/agent.json (the Agent Card).
//
// The governed skill this agent exposes is submit_order, identical to the
// MCP tools/list entry. A caller: 1) calls zk/context (shared with MCP,
// unchanged) to get a request context, 2) has its prover produce an
// envelope bound to that context, 3) calls message/send with a Message
// whose Parts include a DataPart shaped
// {"skill": "submit_order", "arguments": {...}, "zk_attachment": {...}}.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ---------------------------------------------------------------- types

type a2aPart struct {
	Kind string          `json:"kind"`
	Text string          `json:"text,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

type a2aMessage struct {
	Role      string    `json:"role"`
	Parts     []a2aPart `json:"parts"`
	MessageID string    `json:"messageId"`
	TaskID    string    `json:"taskId,omitempty"`
	ContextID string    `json:"contextId,omitempty"`
	Kind      string    `json:"kind"`
}

type a2aTaskStatus struct {
	State   string      `json:"state"`
	Message *a2aMessage `json:"message,omitempty"`
}

type a2aTask struct {
	ID        string        `json:"id"`
	ContextID string        `json:"contextId"`
	Status    a2aTaskStatus `json:"status"`
	Kind      string        `json:"kind"`
}

// taskEntry wraps a2aTask with process-local bookkeeping (createdAt for
// the TTL sweeper) that must never be serialized onto the wire.
type taskEntry struct {
	task      a2aTask
	createdAt time.Time
}

type a2aMessageSendParams struct {
	Message a2aMessage `json:"message"`
}

type a2aTaskQueryParams struct {
	ID string `json:"id"`
}

// a2aSkillInvocation is the shape this gateway expects inside a Message's
// DataPart -- not part of the A2A spec itself (which deliberately leaves
// skill-invocation payloads application-defined), but this repo's own
// convention, symmetric with the MCP tools/call params shape.
type a2aSkillInvocation struct {
	Skill        string          `json:"skill"`
	Arguments    json.RawMessage `json:"arguments"`
	ZkAttachment json.RawMessage `json:"zk_attachment"`
}

// ---------------------------------------------------------------- handlers

func handleMessageSend(state *VenueState, req rpcRequest) rpcResponse {
	var params a2aMessageSendParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return rpcError(req.ID, -32602, "invalid params")
	}

	var invocation a2aSkillInvocation
	found := false
	for _, part := range params.Message.Parts {
		if part.Kind == "data" && len(part.Data) > 0 {
			if err := json.Unmarshal(part.Data, &invocation); err == nil && invocation.Skill != "" {
				found = true
				break
			}
		}
	}
	if !found {
		return rpcResult(req.ID, storeTask(state, failedTask(
			"message did not contain a data part with a skill invocation "+
				"({\"skill\":..., \"arguments\":..., \"zk_attachment\":...})")))
	}

	var args orderArgs
	json.Unmarshal(invocation.Arguments, &args)

	outcome := processGovernedCall(state, invocation.Skill, args.OrderRef, invocation.ZkAttachment)
	if outcome.code != 0 {
		return rpcResult(req.ID, storeTask(state, failedTask(outcome.message)))
	}

	order := Order{OrderRef: args.OrderRef, Symbol: args.Symbol, Side: args.Side, AuditEntry: outcome.auditEntry}
	state.mu.Lock()
	state.orders = append(state.orders, order)
	state.mu.Unlock()

	resultData, _ := json.Marshal(map[string]any{
		"decision":          "ALLOW",
		"audit_entry":       outcome.auditEntry,
		"verify_ms":         round3(outcome.verifyMs),
		"predicate_id":      outcome.predicateID,
		"predicate_version": outcome.predicateVersion,
	})
	text := fmt.Sprintf("order %s ACCEPTED under %s@v%d", args.OrderRef, outcome.predicateID, outcome.predicateVersion)
	return rpcResult(req.ID, storeTask(state, completedTask(text, resultData)))
}

func handleTasksGet(state *VenueState, req rpcRequest) rpcResponse {
	var p a2aTaskQueryParams
	if err := json.Unmarshal(req.Params, &p); err != nil || p.ID == "" {
		return rpcError(req.ID, -32602, "invalid params: id required")
	}
	state.mu.Lock()
	entry, ok := state.tasks[p.ID]
	state.mu.Unlock()
	if !ok {
		return rpcError(req.ID, -32001, "task not found")
	}
	return rpcResult(req.ID, entry.task)
}

func handleTasksCancel(state *VenueState, req rpcRequest) rpcResponse {
	var p a2aTaskQueryParams
	if err := json.Unmarshal(req.Params, &p); err != nil || p.ID == "" {
		return rpcError(req.ID, -32602, "invalid params: id required")
	}
	state.mu.Lock()
	entry, ok := state.tasks[p.ID]
	state.mu.Unlock()
	if !ok {
		return rpcError(req.ID, -32001, "task not found")
	}
	// Every task in this gateway completes synchronously during
	// message/send (proof verification is single-digit milliseconds) --
	// there is never an in-flight task to actually cancel.
	return rpcError(req.ID, -32002, fmt.Sprintf("task already in terminal state: %s", entry.task.Status.State))
}

// ---------------------------------------------------------------- helpers

func failedTask(reason string) a2aTask {
	return a2aTask{
		ID:        randHex(8),
		ContextID: randHex(8),
		Kind:      "task",
		Status: a2aTaskStatus{
			State: "failed",
			Message: &a2aMessage{
				Role:      "agent",
				Kind:      "message",
				MessageID: randHex(8),
				Parts:     []a2aPart{{Kind: "text", Text: "denied: " + trimDeniedPrefix(reason)}},
			},
		},
	}
}

func completedTask(text string, data json.RawMessage) a2aTask {
	return a2aTask{
		ID:        randHex(8),
		ContextID: randHex(8),
		Kind:      "task",
		Status: a2aTaskStatus{
			State: "completed",
			Message: &a2aMessage{
				Role:      "agent",
				Kind:      "message",
				MessageID: randHex(8),
				Parts: []a2aPart{
					{Kind: "text", Text: text},
					{Kind: "data", Data: data},
				},
			},
		},
	}
}

// trimDeniedPrefix avoids "denied: denied: ..." since processGovernedCall's
// messages already start with "denied: " (they're shared with the MCP
// error-message wire format).
func trimDeniedPrefix(s string) string {
	const p = "denied: "
	if len(s) >= len(p) && s[:len(p)] == p {
		return s[len(p):]
	}
	return s
}

func storeTask(state *VenueState, task a2aTask) a2aTask {
	state.mu.Lock()
	state.tasks[task.ID] = &taskEntry{task: task, createdAt: time.Now()}
	state.mu.Unlock()
	return task
}

// agentCardHandler serves the Agent Card at GET /.well-known/agent.json --
// A2A's capability-discovery document, the wire-level analog of MCP's
// tools/list (but fetched before any JSON-RPC call, over plain GET, so a
// caller can discover this agent without already knowing its method
// surface).
func agentCardHandler(port int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		card := map[string]any{
			"name": "execution-venue",
			"description": "Execution-venue agent enforcing zk-attach/v0 governed actions -- " +
				"proves policy compliance (order notional under a pre-trade cap) without " +
				"ever exposing the underlying notional.",
			"url":     fmt.Sprintf("http://localhost:%d/", port),
			"version": "0.1",
			"capabilities": map[string]any{
				"streaming":              false,
				"pushNotifications":      false,
				"stateTransitionHistory": false,
			},
			"defaultInputModes":  []string{"data"},
			"defaultOutputModes": []string{"data"},
			"skills": []any{
				map[string]any{
					"id":   "submit_order",
					"name": "Submit Order",
					"description": "Submit an order for execution. Governed: requires a " +
						"zk_attachment proof for pretrade_notional_cap@v1. Call the zk/context " +
						"JSON-RPC method first to obtain a request context to bind the proof to.",
					"tags":        []string{"trading", "governed", "zk-attach"},
					"inputModes":  []string{"data"},
					"outputModes": []string{"data"},
				},
			},
		}
		data, _ := json.Marshal(card)
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}
}
