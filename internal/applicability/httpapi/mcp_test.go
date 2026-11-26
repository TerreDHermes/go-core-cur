package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cve-patch-viewer/internal/applicability/task"
)

func TestMCPListsFourToolsAndCallsThem(t *testing.T) {
	h := NewHandler(fakeSvc{
		created: "task-1",
		detail: task.Task{
			ID: "task-1", Status: task.StatusCompleted, CVEID: "CVE-2024-1",
			Applicability: task.Applicable,
			Modules: []task.ModuleResult{{
				GoModPath: "./go.mod", Verdict: "Уязвимость применима.", Applicability: task.Applicable,
				ReportMD: task.Report{
					Patch: task.CVEPatch{Files: []task.PatchFile{{Filename: "a.go", Patch: "+fixed"}}},
					PatchFiles: []task.PatchFileMatch{{
						Filename: "a.go", Found: true, Path: "./vendor/example.com/a.go",
					}},
				},
			}},
		},
	}, nil)
	h.UsePatches(stubPatches{status: http.StatusOK, body: []byte(`{"cve":"CVE-2024-1","files":[{"filename":"a.go","patch":"+fixed"},{"filename":"README.md","patch":""}]}`)})
	mux := http.NewServeMux()
	h.Register(mux)

	initRec := mcpPost(t, mux, "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`)
	if initRec.Code != http.StatusOK || !strings.Contains(initRec.Body.String(), `"name":"CVE Verdict"`) {
		t.Fatalf("initialize %d %s", initRec.Code, initRec.Body.String())
	}

	note := mcpPost(t, mux, "/mcp", `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if note.Code != http.StatusAccepted {
		t.Fatalf("notification %d", note.Code)
	}

	list := mcpPost(t, mux, "/api/v1/analysis/mcp", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	for _, name := range []string{"start_analysis", "get_analysis", "get_vulnerability", "get_patch"} {
		if !strings.Contains(list.Body.String(), `"name":"`+name+`"`) {
			t.Fatalf("missing %s in %s", name, list.Body.String())
		}
	}

	started := mcpPost(t, mux, "/mcp", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"start_analysis","arguments":{"component_url":"https://git.slo/dapp/app","branch":"main","cve_id":"CVE-2024-1","package_name":"pkg"}}}`)
	if !strings.Contains(started.Body.String(), "task-1") || !strings.Contains(started.Body.String(), "Анализ запущен") {
		t.Fatal(started.Body.String())
	}

	got := mcpPost(t, mux, "/mcp", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_analysis","arguments":{"component_url":"git@git.slo:dapp/app.git","branch":"main","cve_id":"GHSA-1","package_name":"pkg"}}}`)
	body := got.Body.String()
	for _, part := range []string{"Уязвимость применима.", "vendor/example.com/a.go", "+fixed", "applicable"} {
		if !strings.Contains(body, part) {
			t.Fatalf("missing %s in %s", part, body)
		}
	}

	card := mcpPost(t, mux, "/mcp", `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_vulnerability","arguments":{"id":"CVE-2024-1"}}}`)
	if !strings.Contains(card.Body.String(), "CVE-2024-1") {
		t.Fatal(card.Body.String())
	}

	patch := mcpPost(t, mux, "/mcp", `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"get_patch","arguments":{"id":"CVE-2024-1"}}}`)
	if !strings.Contains(patch.Body.String(), "+fixed") || strings.Contains(patch.Body.String(), "README.md") {
		t.Fatal(patch.Body.String())
	}
}

func TestMCPPatchMissingAndBadCall(t *testing.T) {
	h := NewHandler(fakeSvc{}, nil)
	h.UsePatches(stubPatches{status: http.StatusOK, body: []byte(`{"cve":"CVE-9","files":[{"filename":"README.md","patch":""}]}`)})
	mux := http.NewServeMux()
	h.Register(mux)

	missing := mcpPost(t, mux, "/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_patch","arguments":{"id":"CVE-9"}}}`)
	if !strings.Contains(missing.Body.String(), "патч для CVE-9 не найден") || strings.Contains(missing.Body.String(), `"isError":true`) {
		t.Fatal(missing.Body.String())
	}

	absent := mcpPost(t, mux, "/mcp", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_analysis","arguments":{"component_url":"https://git.slo/a","branch":"main","cve_id":"CVE-1","package_name":"pkg"}}}`)
	if !strings.Contains(absent.Body.String(), "not_started") {
		t.Fatal(absent.Body.String())
	}

	bad := mcpPost(t, mux, "/mcp", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nope","arguments":{}}}`)
	if !strings.Contains(bad.Body.String(), `"isError":true`) {
		t.Fatal(bad.Body.String())
	}

	get := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, get)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatal(rec.Code)
	}
}

func mcpPost(t *testing.T, mux *http.ServeMux, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

type stubPatches struct {
	status int
	body   []byte
	err    error
}

func (s stubPatches) FetchDocument(context.Context, string) (int, []byte, error) {
	return s.status, s.body, s.err
}
