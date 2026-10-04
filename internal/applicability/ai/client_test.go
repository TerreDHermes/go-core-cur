package ai

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCallAIReturnsAssistantText(t *testing.T) {
	var gotAuth, gotModel, gotPrompt string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"model":"test-model"`) {
			t.Errorf("body: %s", body)
		}
		gotModel = "test-model"
		gotPrompt = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"готовый вердикт"}}]}`))
	}))
	defer srv.Close()

	client := NewAIClient(srv.URL+"/", "secret", "test-model")
	text, err := client.CallAI(context.Background(), "промпт")
	if err != nil {
		t.Fatal(err)
	}
	if text != "готовый вердикт" {
		t.Fatal(text)
	}
	if gotAuth != "Bearer secret" || gotModel != "test-model" || !strings.Contains(gotPrompt, "промпт") {
		t.Fatalf("auth %q model %q prompt %s", gotAuth, gotModel, gotPrompt)
	}
}

func TestCallAIRejectsEmptyChoice(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer srv.Close()

	_, err := NewAIClient(srv.URL, "t", "m").CallAI(context.Background(), "x")
	if err == nil || !strings.Contains(err.Error(), "no content") {
		t.Fatal(err)
	}
}

func TestCallAIReturnsStatusBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "busy", http.StatusBadGateway)
	}))
	defer srv.Close()

	_, err := NewAIClient(srv.URL, "t", "m").CallAI(context.Background(), "x")
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatal(err)
	}
}
