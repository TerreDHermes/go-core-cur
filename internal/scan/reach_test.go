package scan

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"cveanalysis/internal/task"
)

func TestFunctionsInPatch(t *testing.T) {
	diff := `diff --git a/sdk/resource/host_id.go b/sdk/resource/host_id.go
@@ -10,6 +10,8 @@ func HostID() string {
 	id := read()
+	if id == "" {
+		return ""
+	}
 	return id
 }
@@ -40,3 +42,3 @@ func (r *Resource) Read() string {
 	return r.name
 }
`
	got := functionsInPatch(diff)
	if len(got) != 2 || got[0].Name != "HostID" || got[0].Recv != "" || got[1].Name != "Read" || got[1].Recv != "Resource" {
		t.Fatal(got)
	}
}

func TestClassifyWhyLive(t *testing.T) {
	if classifyWhyLive(nil, "example.com/app.main\n  static@L0006 --> example.com/app/pkg.HostID\n") != "live" {
		t.Fatal("live")
	}
	if classifyWhyLive(assertErr{}, "deadcode: function example.com/app/pkg.DeadHelper is dead code\n") != "dead" {
		t.Fatal("dead")
	}
	if classifyWhyLive(assertErr{}, "deadcode: function \"missing\" not found in program\n") != "missing" {
		t.Fatal("missing")
	}
	if classifyWhyLive(assertErr{}, "deadcode: no main packages\n") != "no-main" {
		t.Fatal("no main")
	}
	if classifyWhyLive(assertErr{}, "go: cannot find module\n") != "failed" {
		t.Fatal("failed")
	}
}

type assertErr struct{}

func (assertErr) Error() string { return "exit" }

func TestReachableFalseWhenFunctionIsDead(t *testing.T) {
	restore := stubWhyLive(t, func(_ context.Context, dir string, vendor bool, symbol string) (string, string, error) {
		if !vendor || dir == "" {
			t.Fatalf("dir %s vendor %v", dir, vendor)
		}
		if symbol != "go.opentelemetry.io/otel/sdk/resource.HostID" {
			t.Fatalf("symbol %s", symbol)
		}
		return "dead", "deadcode: function go.opentelemetry.io/otel/sdk/resource.HostID is dead code", nil
	})
	defer restore()

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/alertmanager\n\nrequire go.opentelemetry.io/otel/sdk v1.43.0\n")
	mustWrite(t, filepath.Join(root, "vendor", "go.opentelemetry.io", "otel", "sdk", "resource", "host_id.go"), "package resource\n\nfunc HostID() string {\n\treturn read()\n}\n")
	ai := &captureAI{}
	got, err := Scan(context.Background(), Input{
		RepoPath:     root,
		ComponentURL: "https://github.com/prometheus/alertmanager",
		CVEID:        "CVE-2026-24051",
		PackageName:  "go.opentelemetry.io/otel/sdk",
	}, hostPatch{}, ai)
	if err != nil {
		t.Fatal(err)
	}
	reach := got[0].ReportMD.Reach
	if reach == nil || reach.Reachable == nil || *reach.Reachable {
		t.Fatalf("%+v", reach)
	}
	if !strings.Contains(reach.Functions[0].Text, "func HostID") {
		t.Fatal(reach.Functions[0].Text)
	}
	if !strings.Contains(got[0].ReportMD.PreVerdict, "уязвимый код недостижим") {
		t.Fatal(got[0].ReportMD.PreVerdict)
	}
	if !strings.Contains(ai.prompts[0], "неприменима") || !strings.Contains(ai.prompts[0], "недостижим из main") {
		t.Fatal(ai.prompts[0])
	}
}

func TestReachableTrueWhenDeadcodeShowsPath(t *testing.T) {
	restore := stubWhyLive(t, func(context.Context, string, bool, string) (string, string, error) {
		return "live", "example.com/alertmanager/cmd/alertmanager.main\n  static@L0008 --> go.opentelemetry.io/otel/sdk/resource.HostID\n", nil
	})
	defer restore()

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/alertmanager\n\nrequire go.opentelemetry.io/otel/sdk v1.43.0\n")
	mustWrite(t, filepath.Join(root, "vendor", "go.opentelemetry.io", "otel", "sdk", "resource", "host_id.go"), "package resource\n\nfunc HostID() string {\n\treturn read()\n}\n")
	ai := &captureAI{}
	got, err := Scan(context.Background(), Input{
		RepoPath:     root,
		ComponentURL: "https://github.com/prometheus/alertmanager",
		PackageName:  "go.opentelemetry.io/otel/sdk",
		CVEID:        "CVE-2026-24051",
	}, hostPatch{}, ai)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ReportMD.Reach == nil || got[0].ReportMD.Reach.Reachable == nil || !*got[0].ReportMD.Reach.Reachable {
		t.Fatalf("%+v", got[0].ReportMD.Reach)
	}
	if !strings.Contains(got[0].ReportMD.PreVerdict, "код достижим") {
		t.Fatal(got[0].ReportMD.PreVerdict)
	}
	if !strings.Contains(ai.prompts[0], "достижима из main") {
		t.Fatal(ai.prompts[0])
	}
}

func TestDeadcodeFailureDoesNotMeanUnreachable(t *testing.T) {
	restore := stubWhyLive(t, func(context.Context, string, bool, string) (string, string, error) {
		return "failed", "go: build constraints exclude all Go files", nil
	})
	defer restore()

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/alertmanager\n\nrequire go.opentelemetry.io/otel/sdk v1.43.0\n")
	mustWrite(t, filepath.Join(root, "vendor", "go.opentelemetry.io", "otel", "sdk", "resource", "host_id.go"), "package resource\n\nfunc HostID() string { return \"\" }\n")
	got, err := Scan(context.Background(), Input{
		RepoPath:    root,
		PackageName: "go.opentelemetry.io/otel/sdk",
		CVEID:       "CVE-2026-24051",
	}, hostPatch{}, staticAI{})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ReportMD.Reach == nil || got[0].ReportMD.Reach.Reachable != nil {
		t.Fatalf("%+v", got[0].ReportMD.Reach)
	}
	if strings.Contains(got[0].ReportMD.PreVerdict, "уязвимости в этой сборке нет") {
		t.Fatal(got[0].ReportMD.PreVerdict)
	}
}

type hostPatch struct{}

func (hostPatch) Fetch(context.Context, string) (task.CVEPatch, error) {
	return task.CVEPatch{
		CVE: "CVE-2026-24051",
		Files: []task.PatchFile{{
			Filename: "sdk/resource/host_id.go",
			Patch:    "@@ -1,3 +1,4 @@ func HostID() string {\n \treturn read()\n+\treturn \"\"\n }\n",
		}},
	}, nil
}

func stubWhyLive(t *testing.T, fn func(context.Context, string, bool, string) (string, string, error)) func() {
	t.Helper()
	prev := whyLiveFunc
	whyLiveFunc = fn
	return func() { whyLiveFunc = prev }
}
