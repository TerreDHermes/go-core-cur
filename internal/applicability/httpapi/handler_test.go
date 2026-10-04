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
func (f fakeSvc) List(context.Context, tasksvc.ListFilter) ([]task.Task, error) {
	return []task.Task{{
		ID: "1", Status: task.StatusPending, CVEID: "CVE-1",
		ComponentURL: "https://example.com/r", Branch: "main", PackageName: "pkg",
		CreatedAt: "2026-01-01T00:00:00Z",
		Modules:   []task.ModuleResult{{GoModPath: "./go.mod", Verdict: "hidden", ReportMD: task.Report{GoModPath: "./hidden"}}},
	}}, nil
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
