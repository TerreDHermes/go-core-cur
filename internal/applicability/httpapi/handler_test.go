package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cve-patch-viewer/internal/applicability/task"
	"cve-patch-viewer/internal/applicability/tasksvc"
)

type fakeSvc struct {
	created string
}

func (f fakeSvc) Create(context.Context, task.CreateInput) (string, error) {
	return f.created, nil
}
func (f fakeSvc) Open(context.Context, task.CreateInput) (string, error) {
	return f.created, nil
}
func (f fakeSvc) Check(context.Context, task.CreateInput) (string, error) {
	return task.CheckNotStarted, nil
}
func (f fakeSvc) List(context.Context, tasksvc.ListFilter) ([]task.Task, int, error) {
	return []task.Task{{
		ID: "1", Status: task.StatusPending, CVEID: "CVE-1",
		ComponentURL: "https://example.com/r", Branch: "main", PackageName: "pkg",
		CreatedAt: "2026-01-01T00:00:00Z",
		Modules:   []task.ModuleResult{{GoModPath: "./go.mod", Verdict: "hidden", ReportMD: task.Report{GoModPath: "./hidden"}}},
	}}, 7, nil
}
func (f fakeSvc) Get(context.Context, string) (task.Task, error) {
	return task.Task{
		ID: "1", Status: task.StatusCompleted, CVEID: "CVE-1",
		ComponentURL: "https://example.com/r", Branch: "main", PackageName: "pkg",
		Modules: []task.ModuleResult{{
			GoModPath:     "./go.mod",
			Verdict:       "found",
			Applicability: task.Applicable,
			ReportMD:      task.Report{GoModPath: "./go.mod", Narrative: "сначала проверили дерево", Applicability: task.Applicable},
		}},
		Applicability: task.Applicable,
		CreatedAt:     "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:01Z",
	}, nil
}
func (f fakeSvc) Report(context.Context, string) (string, string, error) {
	return "CVE-1", "./go.mod\n", nil
}
func (f fakeSvc) Cancel(context.Context, string) error {
	return nil
}

func TestCancelRoute(t *testing.T) {
	h := NewHandler(fakeSvc{created: "abc"}, nil)
	mux := http.NewServeMux()
	h.Register(mux)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/analysis/abc/cancel", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"FAILED"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestAllowBrowserAnswersPreflight(t *testing.T) {
	h := NewHandler(fakeSvc{created: "abc"}, nil)
	mux := http.NewServeMux()
	h.Register(mux)
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/analysis", nil)
	req.Header.Set("Origin", "http://d49.dev.k8s:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	AllowBrowser(mux).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal(rec.Header().Get("Access-Control-Allow-Origin"))
	}
	if !strings.Contains(rec.Header().Get("Access-Control-Allow-Methods"), "POST") {
		t.Fatal(rec.Header().Get("Access-Control-Allow-Methods"))
	}
}

func TestSwaggerServesSpecAndUI(t *testing.T) {
	h := NewHandler(fakeSvc{created: "abc"}, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/analysis/openapi.json", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("spec status %d body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatal(rec.Header().Get("Content-Type"))
	}
	body := rec.Body.String()
	for _, part := range []string{`"openapi"`, "/api/v1/analysis/{id}", "createAnalysis", "getAnalysis", "openAnalysis", "checkAnalysis"} {
		if !strings.Contains(body, part) {
			t.Fatalf("spec missing %s", part)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/analysis/docs", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("docs redirect %d", rec.Code)
	}
	if rec.Header().Get("Location") != "/api/v1/analysis/docs/" {
		t.Fatal(rec.Header().Get("Location"))
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/analysis/docs/", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ui status %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatal(rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), "/api/v1/analysis/openapi.json") || !strings.Contains(rec.Body.String(), "SwaggerUIBundle") {
		t.Fatal(rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/analysis/docs/swagger-ui-bundle.js", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bundle status %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "SwaggerUIBundle") {
		t.Fatal("bundle did not contain SwaggerUIBundle")
	}
}

func TestModelEndpoints(t *testing.T) {
	h := NewHandler(fakeSvc{created: "abc"}, nil)
	h.UseModels("env-model", func(context.Context) ([]string, error) {
		return []string{"env-model", "other-model"}, nil
	})
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/analysis/default-model", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"model":"env-model"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/analysis/models", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"other-model"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestCreateAndList(t *testing.T) {
	h := NewHandler(fakeSvc{created: "abc"}, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/analysis", strings.NewReader(`{"component_url":"u","branch":"b","cve_id":"c","package_name":"p"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var created map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created["id"] != "abc" {
		t.Fatalf("%v", created)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/analysis", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if strings.Contains(rec.Body.String(), "hidden") || strings.Contains(rec.Body.String(), "report_md") {
		t.Fatalf("list leaked heavy fields: %s", rec.Body.String())
	}
	var listed struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if listed.Total != 7 || len(listed.Items) != 1 || listed.Items[0]["id"] != "1" {
		t.Fatalf("%s", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/analysis/1/report", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if rec.Header().Get("Content-Type") != "text/markdown" {
		t.Fatal(rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Content-Disposition") != `attachment; filename="report-CVE-1.md"` {
		t.Fatal(rec.Header().Get("Content-Disposition"))
	}
	if rec.Body.String() != "./go.mod\n" {
		t.Fatal(rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/analysis/1", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"report_md":"сначала проверили дерево\n"`) || strings.Contains(body, `"has_vendor"`) {
		t.Fatal(body)
	}
	if !strings.Contains(body, `"duration_ms":1000`) || !strings.Contains(body, `"applicability":"applicable"`) {
		t.Fatal(body)
	}
}

func TestOpenRedirectsToAnalysisPage(t *testing.T) {
	h := NewHandler(fakeSvc{created: "abc"}, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/analysis/open?component_url=u&branch=b&cve_id=c&package_name=p", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "/analysis/abc" {
		t.Fatal(rec.Header().Get("Location"))
	}

	h.UseWebBase("http://ui.example/")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "http://ui.example/analysis/abc" {
		t.Fatalf("%d %s", rec.Code, rec.Header().Get("Location"))
	}

	h = NewHandler(openErrSvc{}, nil)
	mux = http.NewServeMux()
	h.Register(mux)
	req = httptest.NewRequest(http.MethodGet, "/api/v1/analysis/open?component_url=u", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

type openErrSvc struct{ fakeSvc }

func (openErrSvc) Open(context.Context, task.CreateInput) (string, error) {
	return "", task.ErrInvalidInput
}
func (openErrSvc) Check(context.Context, task.CreateInput) (string, error) {
	return "", task.ErrInvalidInput
}

func TestCheckReturnsResult(t *testing.T) {
	h := NewHandler(fakeSvc{}, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/analysis/status?component_url=u&branch=b&cve_id=c&package_name=p", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"result":"not_started"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}

	h = NewHandler(openErrSvc{}, nil)
	mux = http.NewServeMux()
	h.Register(mux)
	req = httptest.NewRequest(http.MethodGet, "/api/v1/analysis/status?component_url=u", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}
