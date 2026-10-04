package cveapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestFetchRetriesConnectionResetUntilPatch(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cve/patch/CVE-2025-22869" {
			t.Errorf("path %s", r.URL.Path)
		}
		n := calls.Add(1)
		if n == 1 {
			_, _ = w.Write([]byte(`{"cve":"CVE-2025-22869","message":"mistake in ExtractProjectFromGoCL: read: connection reset by peer"}`))
			return
		}
		_, _ = w.Write([]byte(`{"cve":"CVE-2025-22869","files":[{"filename":"ssh/handshake.go","patch":"diff"}],"project_info":{"project_from_patch":"crypto"}}`))
	}))
	defer srv.Close()

	got, err := (Client{
		BaseURL:    srv.URL,
		HTTP:       srv.Client(),
		RetryPause: time.Millisecond,
	}).Fetch(context.Background(), "CVE-2025-22869")
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls %d", calls.Load())
	}
	if len(got.Files) != 1 || got.Files[0].Patch != "diff" {
		t.Fatalf("%+v", got)
	}
	if got.NeedsPatchRetry() {
		t.Fatal("successful patch still asks for retry")
	}
}
