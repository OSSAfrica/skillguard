package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func testServer() *Server {
	return &Server{Version: "test", Tools: []Entry{{Tool: Tool{Name: "skillguard_test", InputSchema: map[string]any{"type": "object"}}, Call: func(_ context.Context, args json.RawMessage) (any, error) {
		if string(args) == `{"fail":true}` {
			return nil, errors.New("SECRET untrusted parser input")
		}
		return map[string]any{"status": "complete", "execution_authorized": false}, nil
	}}}}
}
func exchange(t *testing.T, wire string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := testServer().Serve(context.Background(), strings.NewReader(wire), &out); err != nil {
		t.Fatal(err)
	}
	var values []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var value map[string]any
		if json.Unmarshal([]byte(line), &value) != nil {
			t.Fatalf("non-protocol stdout: %q", line)
		}
		values = append(values, value)
	}
	if strings.Contains(out.String(), "SECRET") {
		t.Fatal("untrusted errors leaked")
	}
	return values
}

const initRequest = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}` + "\n"

func TestInitializationAndToolCalls(t *testing.T) {
	replies := exchange(t, initRequest+`{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"+`{"jsonrpc":"2.0","id":"tools","method":"tools/list","params":{}}`+"\n"+`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"skillguard_test","arguments":{}}}`+"\n")
	if len(replies) != 3 {
		t.Fatal(replies)
	}
	if replies[0]["result"].(map[string]any)["protocolVersion"] != "2025-06-18" {
		t.Fatal("invalid negotiation")
	}
	result := replies[2]["result"].(map[string]any)
	if result["isError"] != false || result["structuredContent"].(map[string]any)["execution_authorized"] != false {
		t.Fatal(result)
	}
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	if !json.Valid([]byte(text)) {
		t.Fatal("compatibility text not JSON")
	}
}
func TestProtocolErrorsAndFailureAreBounded(t *testing.T) {
	for _, wire := range []string{`not-json`, `[]`, `{"jsonrpc":"2.0","id":{},"method":"ping"}`, `{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/list"}`, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`} {
		replies := exchange(t, wire+"\n")
		if len(replies) != 1 || replies[0]["error"] == nil {
			t.Fatalf("invalid accepted: %s", wire)
		}
	}
	replies := exchange(t, initRequest+`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"skillguard_test","arguments":{"fail":true}}}`+"\n")
	if replies[1]["result"].(map[string]any)["isError"] != true {
		t.Fatal("tool failure passed")
	}
}
func TestLimitsAndNotifications(t *testing.T) {
	var out bytes.Buffer
	err := testServer().Serve(context.Background(), strings.NewReader(strings.Repeat("x", MaxMessage+1)), &out)
	if err == nil {
		t.Fatal("oversized message accepted")
	}
	if replies := exchange(t, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`+"\n"); len(replies) != 0 {
		t.Fatal("notification replied")
	}
}
