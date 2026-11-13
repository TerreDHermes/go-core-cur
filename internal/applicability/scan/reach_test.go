package scan

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"cve-patch-viewer/internal/applicability/task"
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

func TestParseDeadcodeListsUnreachableSymbols(t *testing.T) {
	raw := `[
		{"Name":"jose","Path":"github.com/go-jose/go-jose/v4","Funcs":[
			{"Name":"rawJSONWebSignature.sanitized","Position":{"File":"jws.go","Line":10,"Col":6},"Generated":false}
		]},
		{"Name":"resource","Path":"go.opentelemetry.io/otel/sdk/resource","Funcs":[
			{"Name":"HostID","Position":{"File":"host_id.go","Line":4,"Col":6},"Generated":false}
		]}
	]`
	dead, err := parseDeadcode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := dead["github.com/go-jose/go-jose/v4.rawJSONWebSignature.sanitized"]; !ok {
		t.Fatal(dead)
	}
	if _, ok := dead["go.opentelemetry.io/otel/sdk/resource.HostID"]; !ok {
		t.Fatal(dead)
	}
	empty, err := parseDeadcode("null")
	if err != nil || len(empty) != 0 {
		t.Fatal(err, empty)
	}
	if _, err := parseDeadcode(""); err == nil {
		t.Fatal("empty output")
	}
}

func TestClassifyModuleSymbol(t *testing.T) {
	dead := map[string]struct{}{"example.com/app/pkg.DeadHelper": {}}
	if status, _ := classifyModuleSymbol(moduleDeadcode{Status: "ok", Dead: dead}, "example.com/app/pkg.DeadHelper"); status != "dead" {
		t.Fatal(status)
	}
	if status, _ := classifyModuleSymbol(moduleDeadcode{Status: "ok", Dead: dead}, "example.com/app/pkg.HostID"); status != "live" {
		t.Fatal(status)
	}
	if status, _ := classifyModuleSymbol(moduleDeadcode{Status: "no-main", Output: "deadcode: no main packages"}, "example.com/app/pkg.HostID"); status != "no-main" {
		t.Fatal(status)
	}
	if status, out := classifyModuleSymbol(moduleDeadcode{Status: "failed", Output: deadcodeTimeoutOutput()}, "example.com/app/pkg.HostID"); status != "failed" || !strings.Contains(out, "4 минуты") {
		t.Fatal(status, out)
	}
}

func TestMemLimitUsesThreeQuarters(t *testing.T) {
	got, ok := memLimitValue("16384")
	if ok {
		t.Fatal(got)
	}
	got, ok = memLimitValue("max")
	if ok {
		t.Fatal(got)
	}
	got, ok = memLimitValue("17179869184")
	if !ok || got != strconv.FormatUint(17179869184*3/4/uint64(deadcodeSlots), 10) {
		t.Fatal(got, ok)
	}
	if deadcodeLimit != 4*time.Minute || deadcodeSlots != 2 {
		t.Fatal(deadcodeLimit, deadcodeSlots)
	}
	if !strings.Contains(strings.Join(deadcodeArgs(), " "), "-filter=") || !strings.Contains(strings.Join(deadcodeArgs(), " "), "-json") {
		t.Fatal(deadcodeArgs())
	}
}

func TestReachableFalseWhenFunctionIsDead(t *testing.T) {
	restore := stubModuleDeadcode(t, func(_ context.Context, dir string, vendor bool) moduleDeadcode {
		if !vendor || dir == "" {
			t.Fatalf("dir %s vendor %v", dir, vendor)
		}
		return moduleDeadcode{Status: "ok", Dead: map[string]struct{}{
			"go.opentelemetry.io/otel/sdk/resource.HostID": {},
		}}
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
	if got[0].Applicability != task.NotApplicable {
		t.Fatal(got[0].Applicability)
	}
	if !strings.Contains(ai.prompts[0], "неприменима") || !strings.Contains(ai.prompts[0], "недостижим из main") {
		t.Fatal(ai.prompts[0])
	}
}

func TestReachableTrueWhenDeadcodeShowsPath(t *testing.T) {
	restore := stubModuleDeadcode(t, func(context.Context, string, bool) moduleDeadcode {
		return moduleDeadcode{Status: "ok", Dead: map[string]struct{}{}}
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
	if got[0].Applicability != task.Applicable {
		t.Fatal(got[0].Applicability)
	}
	if !strings.Contains(ai.prompts[0], "достижима из main") {
		t.Fatal(ai.prompts[0])
	}
}

func TestDeadcodeFailureDoesNotMeanUnreachable(t *testing.T) {
	restore := stubModuleDeadcode(t, func(context.Context, string, bool) moduleDeadcode {
		return moduleDeadcode{Status: "failed", Output: "go: build constraints exclude all Go files"}
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
	if got[0].Applicability != task.Uncertain {
		t.Fatal(got[0].Applicability)
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

func TestOneDeadcodeRunCoversEverySymbol(t *testing.T) {
	calls := 0
	restore := stubModuleDeadcode(t, func(context.Context, string, bool) moduleDeadcode {
		calls++
		return moduleDeadcode{Status: "ok", Dead: map[string]struct{}{
			"go.opentelemetry.io/otel/sdk/resource.HostID": {},
		}}
	})
	defer restore()

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/alertmanager\n")
	rel := "vendor/go.opentelemetry.io/otel/sdk/resource/host_id.go"
	mustWrite(t, filepath.Join(root, rel), "package resource\n\nfunc HostID() string { return \"\" }\nfunc readMachineID() string { return \"\" }\n")
	diff := "@@ func HostID() string {\n+func readMachineID() string {\n"
	report := analyzeReach(context.Background(), root, []task.PatchFile{{
		Filename: "sdk/resource/host_id.go",
		Patch:    diff,
	}}, []task.PatchFileMatch{{
		Filename: "sdk/resource/host_id.go",
		Found:    true,
		Path:     rel,
	}})
	if calls != 1 {
		t.Fatal(calls)
	}
	if report.Reachable == nil || !*report.Reachable {
		t.Fatalf("%+v", report)
	}
	if len(report.Functions) != 2 || report.Functions[0].Status != "dead" || report.Functions[1].Status != "live" {
		t.Fatalf("%+v", report.Functions)
	}
}

func TestTimeoutDetailStaysUnknown(t *testing.T) {
	detail := unknownDetail([]task.ReachFunc{{
		Status: "failed",
		Output: deadcodeTimeoutOutput(),
	}})
	if !strings.Contains(detail, "4 минуты") || !strings.Contains(detail, "не проверена") {
		t.Fatal(detail)
	}
	reachable, _ := summarizeReach([]task.ReachFunc{{Status: "failed", Output: deadcodeTimeoutOutput()}})
	if reachable != nil {
		t.Fatal(reachable)
	}
}

func TestRunGroupedKillsGrandchild(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	childFile := filepath.Join(dir, "child")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		script := "sleep 30 & echo $! > " + strconv.Quote(childFile) + "; wait"
		_, _, _ = runGrouped(ctx, dir, os.Environ(), "bash", "-c", script)
	}()
	var pid string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		body, err := os.ReadFile(childFile)
		if err == nil && strings.TrimSpace(string(body)) != "" {
			pid = strings.TrimSpace(string(body))
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pid == "" {
		cancel()
		<-done
		t.Fatal("child pid was not written")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("grouped command did not return")
	}
	if _, err := os.Stat("/proc/" + pid); err == nil {
		t.Fatalf("child %s still alive", pid)
	}
}

func TestDeadcodeGateHoldsTheThird(t *testing.T) {
	held := holdDeadcodeSlots(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err := acquireDeadcode(ctx); err == nil {
		t.Fatal("third run took a slot")
	}
	releaseDeadcode()
	*held--
	if err := acquireDeadcode(context.Background()); err != nil {
		t.Fatal(err)
	}
	releaseDeadcode()
}

func TestDeadcodeGateCancelDoesNotTakeASlot(t *testing.T) {
	holdDeadcodeSlots(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := acquireDeadcode(ctx); err == nil {
		t.Fatal("cancelled task took a slot")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err := acquireDeadcode(ctx); err == nil {
		t.Fatal("cancel freed a slot")
	}
}

func TestDeadcodeWaitKeepsTheModule(t *testing.T) {
	p := NewProgress()
	ctx := WithProgress(context.Background(), p)
	noteAt(ctx, "проверка достижимости", "github.com/cilium/cilium", 1, 1)
	done := make(chan struct{})
	t.Cleanup(func() { <-done })
	held := holdDeadcodeSlots(t)
	go func() {
		defer close(done)
		if err := acquireDeadcode(ctx); err == nil {
			releaseDeadcode()
		}
	}()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !strings.Contains(p.Line(), "ожидание deadcode") {
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(p.Line(), "ожидание deadcode") || !strings.Contains(p.Line(), "github.com/cilium/cilium") {
		t.Fatal(p.Line())
	}
	releaseDeadcode()
	*held--
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("did not leave the queue")
	}
	if !strings.Contains(p.Line(), "проверка достижимости") || !strings.Contains(p.Line(), "github.com/cilium/cilium") {
		t.Fatal(p.Line())
	}
}

func holdDeadcodeSlots(t *testing.T) *int {
	t.Helper()
	held := deadcodeSlots
	for i := 0; i < deadcodeSlots; i++ {
		if err := acquireDeadcode(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for held > 0 {
			releaseDeadcode()
			held--
		}
	})
	return &held
}

func stubModuleDeadcode(t *testing.T, fn func(context.Context, string, bool) moduleDeadcode) func() {
	t.Helper()
	prev := runModuleDeadcode
	runModuleDeadcode = fn
	return func() { runModuleDeadcode = prev }
}
