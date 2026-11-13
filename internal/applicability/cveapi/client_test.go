package cveapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestFetchTimeoutLadderStops(t *testing.T) {
	var calls atomic.Int32
	var gaps []time.Duration
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-r.Context().Done()
	}))
	defer srv.Close()

	limits := []time.Duration{40 * time.Millisecond, 90 * time.Millisecond, 140 * time.Millisecond}
	_, err := (Client{
		BaseURL:         srv.URL,
		HTTP:            clientWithDeadlines(srv.Client(), &gaps),
		RetryPause:      time.Millisecond,
		AttemptTimeouts: limits,
	}).Fetch(context.Background(), "CVE-2025-22869")
	if err == nil || !strings.Contains(err.Error(), "timed out after 140ms") {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls %d", calls.Load())
	}
	if len(gaps) != 3 || gaps[0] >= gaps[1] || gaps[1] >= gaps[2] {
		t.Fatal(gaps)
	}
}

func TestFetchTimeoutThenResetRestartsAtShortLimit(t *testing.T) {
	var calls atomic.Int32
	var gaps []time.Duration
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		switch n {
		case 1:
			<-r.Context().Done()
		case 2:
			_, _ = w.Write([]byte(`{"cve":"CVE-2025-22869","message":"read: connection reset by peer"}`))
		default:
			_, _ = w.Write([]byte(`{"cve":"CVE-2025-22869","files":[{"filename":"ssh/handshake.go","patch":"diff"}]}`))
		}
	}))
	defer srv.Close()

	got, err := (Client{
		BaseURL:         srv.URL,
		HTTP:            clientWithDeadlines(srv.Client(), &gaps),
		RetryPause:      time.Millisecond,
		AttemptTimeouts: []time.Duration{40 * time.Millisecond, 100 * time.Millisecond, 160 * time.Millisecond},
	}).Fetch(context.Background(), "CVE-2025-22869")
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 || len(got.Files) != 1 {
		t.Fatalf("calls %d %+v", calls.Load(), got)
	}
	if len(gaps) != 3 || gaps[1] <= gaps[0] || gaps[2] >= gaps[1] {
		t.Fatal(gaps)
	}
}

func TestFetchOtherErrorDoesNotRetry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"message":"upstream down"}`))
	}))
	defer srv.Close()

	_, err := (Client{
		BaseURL:         srv.URL,
		HTTP:            srv.Client(),
		RetryPause:      time.Millisecond,
		AttemptTimeouts: []time.Duration{time.Second, time.Second, time.Second},
	}).Fetch(context.Background(), "CVE-2025-22869")
	if err == nil || !strings.Contains(err.Error(), "status 502") {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls %d", calls.Load())
	}
}

func TestFetchParentCancelDoesNotClimb(t *testing.T) {
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		cancel()
		<-r.Context().Done()
	}))
	defer srv.Close()

	_, err := (Client{
		BaseURL:         srv.URL,
		HTTP:            srv.Client(),
		RetryPause:      time.Millisecond,
		AttemptTimeouts: []time.Duration{time.Second, time.Second, time.Second},
	}).Fetch(ctx, "CVE-2025-22869")
	if err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), "timed out") || calls.Load() != 1 {
		t.Fatal(err, calls.Load())
	}
}

func TestFetchKeepsLaterAttemptWhenClientTimeoutIsShort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(40 * time.Millisecond)
		_, _ = w.Write([]byte(`{"cve":"CVE-2025-22869","files":[{"filename":"a.go","patch":"diff"}]}`))
	}))
	defer srv.Close()

	httpClient := srv.Client()
	httpClient.Timeout = 15 * time.Millisecond
	got, err := (Client{
		BaseURL:         srv.URL,
		HTTP:            httpClient,
		RetryPause:      time.Millisecond,
		AttemptTimeouts: []time.Duration{120 * time.Millisecond},
	}).Fetch(context.Background(), "CVE-2025-22869")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 1 {
		t.Fatalf("%+v", got)
	}
}

type deadlineTransport struct {
	base http.RoundTripper
	gaps *[]time.Duration
}

func (d deadlineTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if dl, ok := r.Context().Deadline(); ok {
		*d.gaps = append(*d.gaps, time.Until(dl))
	}
	return d.base.RoundTrip(r)
}

func clientWithDeadlines(base *http.Client, gaps *[]time.Duration) *http.Client {
	return &http.Client{Transport: deadlineTransport{base: base.Transport, gaps: gaps}}
}
