package main

import (
	"encoding/json"
	"testing"
)

func TestTrimDeniedPrefix(t *testing.T) {
	if got := trimDeniedPrefix("denied: wrong predicate for this tool"); got != "wrong predicate for this tool" {
		t.Fatalf("got %q", got)
	}
	if got := trimDeniedPrefix("unknown tool: foo"); got != "unknown tool: foo" {
		t.Fatalf("expected unprefixed message to pass through unchanged, got %q", got)
	}
}

func TestFailedTask_Shape(t *testing.T) {
	task := failedTask("something went wrong")
	if task.Status.State != "failed" {
		t.Fatalf("expected state=failed, got %q", task.Status.State)
	}
	if task.Kind != "task" {
		t.Fatalf("expected kind=task, got %q", task.Kind)
	}
	if task.Status.Message == nil || len(task.Status.Message.Parts) != 1 {
		t.Fatal("expected exactly one message part")
	}
	if task.Status.Message.Parts[0].Kind != "text" {
		t.Fatalf("expected a text part, got %q", task.Status.Message.Parts[0].Kind)
	}
}

func TestCompletedTask_Shape(t *testing.T) {
	data, _ := json.Marshal(map[string]any{"decision": "ALLOW"})
	task := completedTask("order accepted", data)
	if task.Status.State != "completed" {
		t.Fatalf("expected state=completed, got %q", task.Status.State)
	}
	if len(task.Status.Message.Parts) != 2 {
		t.Fatalf("expected a text part and a data part, got %d parts", len(task.Status.Message.Parts))
	}
	if task.Status.Message.Parts[0].Kind != "text" || task.Status.Message.Parts[1].Kind != "data" {
		t.Fatal("expected parts in [text, data] order")
	}
}

func TestHandleMessageSend_MissingDataPart(t *testing.T) {
	state := &VenueState{tasks: map[string]*taskEntry{}}
	req := rpcRequest{
		ID:     json.RawMessage(`1`),
		Method: "message/send",
		Params: json.RawMessage(`{"message":{"role":"user","kind":"message","messageId":"m1","parts":[{"kind":"text","text":"hello"}]}}`),
	}
	resp := handleMessageSend(state, req)
	task, ok := resp.Result.(a2aTask)
	if !ok {
		t.Fatalf("expected an a2aTask result, got %T", resp.Result)
	}
	if task.Status.State != "failed" {
		t.Fatalf("expected a message with no data part to fail, got state=%q", task.Status.State)
	}
}

func TestHandleMessageSend_MissingAttachmentDeniedByDefault(t *testing.T) {
	state := &VenueState{tasks: map[string]*taskEntry{}, contexts: map[string]*ctxEntry{}}
	req := rpcRequest{
		ID:     json.RawMessage(`1`),
		Method: "message/send",
		Params: json.RawMessage(`{"message":{"role":"user","kind":"message","messageId":"m1","parts":[
			{"kind":"data","data":{"skill":"submit_order","arguments":{"order_ref":"ord-1"}}}
		]}}`),
	}
	resp := handleMessageSend(state, req)
	task, ok := resp.Result.(a2aTask)
	if !ok {
		t.Fatalf("expected an a2aTask result, got %T", resp.Result)
	}
	if task.Status.State != "failed" {
		t.Fatalf("expected deny-by-default (no zk_attachment) to fail, got state=%q", task.Status.State)
	}
	if task.Status.Message.Parts[0].Text != "denied: governed tool requires zk_attachment (deny-by-default)" {
		t.Fatalf("unexpected denial message: %q", task.Status.Message.Parts[0].Text)
	}
}

func TestHandleTasksGetAndCancel_NotFound(t *testing.T) {
	state := &VenueState{tasks: map[string]*taskEntry{}}
	req := rpcRequest{ID: json.RawMessage(`1`), Params: json.RawMessage(`{"id":"nope"}`)}

	if resp := handleTasksGet(state, req); resp.Error == nil || resp.Error.Code != -32001 {
		t.Fatalf("expected task-not-found error, got %+v", resp)
	}
	if resp := handleTasksCancel(state, req); resp.Error == nil || resp.Error.Code != -32001 {
		t.Fatalf("expected task-not-found error, got %+v", resp)
	}
}
