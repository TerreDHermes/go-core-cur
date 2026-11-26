package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cve-patch-viewer/internal/applicability/cveapi"
)

func TestCVECardReturnsAnalyzerBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cve/patch/CVE-2024-0001" {
			t.Errorf("path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"cve":"CVE-2024-0001","description":"hole","files":[{"filename":"a.go","patch":"diff"}],"vendor_note":"keep"}`))
	}))
	defer upstream.Close()

	h := NewHandler(fakeSvc{}, nil)
	h.UsePatches(cveapi.Client{BaseURL: upstream.URL, HTTP: upstream.Client(), RetryPause: time.Millisecond})
	mux := http.NewServeMux()
	h.Register(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/analysis/cve/CVE-2024-0001/info", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"vendor_note":"keep"`) || strings.Contains(rec.Body.String(), `"verdict"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestCVEPatchReturnsOnlyFiles(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"cve":"CVE-2024-0001","description":"hole","files":[{"filename":"a.go","patch":"diff","extra":1},{"filename":"empty.go","patch":"  "}]}`))
	}))
	defer upstream.Close()

	h := NewHandler(fakeSvc{}, nil)
	h.UsePatches(cveapi.Client{BaseURL: upstream.URL, HTTP: upstream.Client(), RetryPause: time.Millisecond})
	mux := http.NewServeMux()
	h.Register(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/analysis/cve/CVE-2024-0001/patch", nil))
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code, rec.Body.String())
	}
	var got struct {
		CVE         string `json:"cve"`
		Description string `json:"description"`
		Files       []struct {
			Filename string `json:"filename"`
			Patch    string `json:"patch"`
			Extra    int    `json:"extra"`
		} `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.CVE != "CVE-2024-0001" || got.Description != "" || len(got.Files) != 1 || got.Files[0].Extra != 1 || got.Files[0].Patch != "diff" {
		t.Fatalf("%+v", got)
	}
}

func TestCVEPatchMissingIsNotFound(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"cve":"CVE-2024-0001","description":"hole"}`))
	}))
	defer upstream.Close()

	h := NewHandler(fakeSvc{}, nil)
	h.UsePatches(cveapi.Client{BaseURL: upstream.URL, HTTP: upstream.Client(), RetryPause: time.Millisecond})
	mux := http.NewServeMux()
	h.Register(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/analysis/cve/CVE-2024-0001/patch", nil))
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "патч для CVE-2024-0001 не найден") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestCVECardPassesAnalyzerError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"unknown id"}`))
	}))
	defer upstream.Close()

	h := NewHandler(fakeSvc{}, nil)
	h.UsePatches(cveapi.Client{BaseURL: upstream.URL, HTTP: upstream.Client(), RetryPause: time.Millisecond})
	mux := http.NewServeMux()
	h.Register(mux)

	for _, path := range []string{"/api/v1/analysis/cve/CVE-missing/info", "/api/v1/analysis/cve/CVE-missing/patch"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "unknown id") {
			t.Fatalf("%s %d %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestCVECardRetriesReset(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			_, _ = w.Write([]byte(`{"cve":"CVE-2024-0001","message":"read: connection reset by peer"}`))
			return
		}
		_, _ = w.Write([]byte(`{"cve":"CVE-2024-0001","files":[{"filename":"a.go","patch":"diff"}]}`))
	}))
	defer upstream.Close()

	h := NewHandler(fakeSvc{}, nil)
	h.UsePatches(cveapi.Client{BaseURL: upstream.URL, HTTP: upstream.Client(), RetryPause: time.Millisecond})
	mux := http.NewServeMux()
	h.Register(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/analysis/cve/CVE-2024-0001/info", nil))
	if rec.Code != http.StatusOK || calls.Load() != 2 || !strings.Contains(rec.Body.String(), `"patch":"diff"`) {
		t.Fatalf("calls %d %d %s", calls.Load(), rec.Code, rec.Body.String())
	}
}

func TestSwaggerListsCVERoutes(t *testing.T) {
	body := openAPISpec
	if !json.Valid(body) {
		t.Fatal("openapi.json")
	}
	text := string(body)
	for _, part := range []string{"/api/v1/analysis/cve/{id}/info", "/api/v1/analysis/cve/{id}/patch", "getCVE", "getCVEPatch"} {
		if !strings.Contains(text, part) {
			t.Fatal(part)
		}
	}
	var spec struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(body, &spec); err != nil {
		t.Fatal(err)
	}
	if _, ok := spec.Paths["/api/v1/analysis/cve/{id}/patch"]; !ok {
		t.Fatal("patch path missing")
	}
}

func TestCVECardWithoutClient(t *testing.T) {
	h := NewHandler(fakeSvc{}, nil)
	mux := http.NewServeMux()
	h.Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/analysis/cve/CVE-2024-0001/info", nil))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "не настроен") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}
