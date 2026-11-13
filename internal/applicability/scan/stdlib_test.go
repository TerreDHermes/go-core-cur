package scan

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cve-patch-viewer/internal/applicability/task"
)

func TestGoRelease(t *testing.T) {
	cases := []struct {
		body      string
		toolchain string
		pinned    bool
		line      string
	}{
		{"module example.com/app\n\ngo 1.22.5\n", "go1.22.5", true, "go 1.22.5"},
		{"module example.com/app\r\n\r\ngo 1.22.5\r\n", "go1.22.5", true, "go 1.22.5"},
		{"go 1.22.5 // pin\n", "go1.22.5", true, "go 1.22.5"},
		{"go 1.22.0\n", "go1.22.0", true, "go 1.22.0"},
		{"go 1.21.0\ntoolchain go1.22.5\n", "go1.22.5", true, "toolchain go1.22.5"},
		{"go 1.22.5\ntoolchain local\n", "go1.22.5", true, "go 1.22.5"},
		{"go 1.22.5\ntoolchain default\n", "go1.22.5", true, "go 1.22.5"},
		{"go 1.22\n", "", false, "go 1.22"},
		{"go 1.22.5\ntoolchain go1.22\n", "", false, "toolchain go1.22"},
		{"module example.com/app\n", "", false, ""},
	}
	for _, tc := range cases {
		got := goReleaseOf(tc.body)
		if got.Pinned != tc.pinned || got.Toolchain != tc.toolchain || got.Line != tc.line {
			t.Fatalf("%q: %+v", tc.body, got)
		}
	}
}

func TestLocateStdlibFiles(t *testing.T) {
	goroot := t.TempDir()
	mustWrite(t, filepath.Join(goroot, "src", "crypto", "tls", "conn.go"), "package tls\n")
	mustWrite(t, filepath.Join(goroot, "secret"), "nope\n")
	files := []task.PatchFile{
		{Filename: "src/crypto/tls/conn.go"},
		{Filename: "crypto/tls/conn.go"},
		{Filename: "src/../secret"},
		{Filename: "../secret"},
		{Filename: "src/crypto/tls/missing.go"},
	}
	got := locateStdlibFiles(goroot, files)
	if !got[0].Found || !got[1].Found {
		t.Fatal(got)
	}
	if got[0].Path != got[1].Path {
		t.Fatal(got[0].Path, got[1].Path)
	}
	if !strings.HasSuffix(filepath.ToSlash(got[0].Path), "src/crypto/tls/conn.go") {
		t.Fatal(got[0].Path)
	}
	for _, match := range got[2:] {
		if match.Found {
			t.Fatal(match)
		}
	}
	if stdlibImportPath(goroot, got[0].Path) != "crypto/tls" {
		t.Fatal(stdlibImportPath(goroot, got[0].Path))
	}
}

func TestStdlibUnpinnedDoesNotDownload(t *testing.T) {
	lookups := 0
	stubLookup(t, func(context.Context, string, string) (string, error) {
		lookups++
		return "", nil
	})
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.22\n")
	got := scanStdlibCase(t, root, stdlibOneFile("src/crypto/tls/conn.go", "fixed"))
	if lookups != 0 {
		t.Fatal(lookups)
	}
	if got.Applicability != task.Uncertain || got.ReportMD.Stage != task.StageStdlibUnpinned {
		t.Fatalf("%s %s", got.Applicability, got.ReportMD.Stage)
	}
	if !strings.Contains(got.ReportMD.PreVerdict, "не закреплён") || !strings.Contains(got.ReportMD.PreVerdict, "go 1.22") {
		t.Fatal(got.ReportMD.PreVerdict)
	}
	if strings.Contains(got.Verdict, "vendor") {
		t.Fatal(got.Verdict)
	}
}

func TestStdlibDownloadFailure(t *testing.T) {
	stubLookup(t, func(context.Context, string, string) (string, error) {
		return "", errString("proxy refused")
	})
	deadcode := 0
	restore := stubModuleDeadcode(t, func(context.Context, string, bool) moduleDeadcode {
		deadcode++
		return moduleDeadcode{Status: "ok"}
	})
	defer restore()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.22.5\n")
	got := scanStdlibCase(t, root, stdlibOneFile("src/crypto/tls/conn.go", "fixed"))
	if deadcode != 0 {
		t.Fatal(deadcode)
	}
	if got.Applicability != task.Uncertain || got.ReportMD.Stage != task.StageStdlibNoSource {
		t.Fatalf("%s %s", got.Applicability, got.ReportMD.Stage)
	}
	if got.ReportMD.Version != "go1.22.5" {
		t.Fatal(got.ReportMD.Version)
	}
	if !strings.Contains(got.ReportMD.PreVerdict, "по версии уязвима") || !strings.Contains(got.ReportMD.PreVerdict, "proxy refused") || !strings.Contains(got.ReportMD.PreVerdict, "Досягаемость не проверялась") {
		t.Fatal(got.ReportMD.PreVerdict)
	}
	if !strings.Contains(got.Verdict, "не скачались") {
		t.Fatal(got.Verdict)
	}
}

func TestStdlibCancelDuringDownload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stubLookup(t, func(context.Context, string, string) (string, error) {
		cancel()
		return "", ctx.Err()
	})
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.22.5\n")
	_, err := Scan(ctx, Input{RepoPath: root, CVEID: "CVE-2026-1", PackageName: "stdlib"}, stdlibOneFile("src/crypto/tls/conn.go", "fixed"), staticAI{})
	if err == nil {
		t.Fatal("cancelled download must fail the task")
	}
}

func TestStdlibPackageNotImported(t *testing.T) {
	goroot := writeStdlibFile(t, "crypto/tls/conn.go", hostBody("vuln"))
	stubLookup(t, func(context.Context, string, string) (string, error) {
		return goroot, nil
	})
	var listed []bool
	stubList(t, func(_ context.Context, _ string, vendor bool) (map[string]struct{}, error) {
		listed = append(listed, vendor)
		return map[string]struct{}{"fmt": {}}, nil
	})
	deadcode := 0
	restore := stubModuleDeadcode(t, func(context.Context, string, bool) moduleDeadcode {
		deadcode++
		return moduleDeadcode{Status: "ok"}
	})
	defer restore()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.22.5\n")
	mustWrite(t, filepath.Join(root, "vendor", "modules.txt"), "# vendor\n")
	got := scanStdlibCase(t, root, stdlibOneFile("src/crypto/tls/conn.go", "fixed"))
	if deadcode != 0 || len(listed) != 1 || !listed[0] {
		t.Fatalf("deadcode %d listed %v", deadcode, listed)
	}
	if got.Applicability != task.NotApplicable {
		t.Fatal(got.Applicability, got.ReportMD.PreVerdict)
	}
	if !strings.Contains(got.ReportMD.PreVerdict, "не импортирует") {
		t.Fatal(got.ReportMD.PreVerdict)
	}
	if len(got.ReportMD.Reach.Functions) != 1 || got.ReportMD.Reach.Functions[0].Symbol != "crypto/tls.HostID" {
		t.Fatalf("%+v", got.ReportMD.Reach)
	}
}

func TestStdlibReachableWhenImported(t *testing.T) {
	goroot := writeStdlibFile(t, "crypto/tls/conn.go", hostBody("vuln"))
	var gotToolchain []string
	stubLookup(t, func(_ context.Context, _ string, name string) (string, error) {
		gotToolchain = append(gotToolchain, name)
		return goroot, nil
	})
	stubList(t, func(ctx context.Context, dir string, vendor bool) (map[string]struct{}, error) {
		if toolchainFrom(ctx) != "go1.21.0" || vendor {
			t.Fatalf("list %s vendor %v", toolchainFrom(ctx), vendor)
		}
		return map[string]struct{}{"crypto/tls": {}}, nil
	})
	var dirs []string
	restore := stubModuleDeadcode(t, func(ctx context.Context, dir string, vendor bool) moduleDeadcode {
		if toolchainFrom(ctx) != "go1.21.0" || vendor {
			t.Fatalf("deadcode %s vendor %v", toolchainFrom(ctx), vendor)
		}
		dirs = append(dirs, dir)
		return moduleDeadcode{Status: "ok"}
	})
	defer restore()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.21.0\n\ntoolchain local\n")
	got := scanStdlibCase(t, root, stdlibOneFile("src/crypto/tls/conn.go", "fixed"))
	if len(gotToolchain) != 1 || gotToolchain[0] != "go1.21.0" {
		t.Fatal(gotToolchain)
	}
	if len(dirs) != 1 || dirs[0] != root {
		t.Fatal(dirs)
	}
	if got.Applicability != task.Applicable || got.ReportMD.Version != "go1.21.0" {
		t.Fatalf("%s %s %s", got.Applicability, got.ReportMD.Version, got.Verdict)
	}
	if !strings.Contains(got.Verdict, "стандартная библиотека Go go1.21.0") || !strings.Contains(got.Verdict, "достижима") {
		t.Fatal(got.Verdict)
	}
	if got.ReportMD.Reach.Functions[0].Symbol != "crypto/tls.HostID" {
		t.Fatal(got.ReportMD.Reach.Functions[0].Symbol)
	}
}

func TestStdlibToolchainLineWins(t *testing.T) {
	goroot := writeStdlibFile(t, "crypto/tls/conn.go", hostBody("fixed"))
	var name string
	stubLookup(t, func(_ context.Context, _ string, toolchain string) (string, error) {
		name = toolchain
		return goroot, nil
	})
	stubList(t, func(context.Context, string, bool) (map[string]struct{}, error) {
		return map[string]struct{}{"crypto/tls": {}}, nil
	})
	restore := stubModuleDeadcode(t, func(context.Context, string, bool) moduleDeadcode {
		return moduleDeadcode{Status: "ok"}
	})
	defer restore()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.21.0\n\ntoolchain go1.22.5\n")
	got := scanStdlibCase(t, root, stdlibOneFile("src/crypto/tls/conn.go", "fixed"))
	if name != "go1.22.5" || got.ReportMD.Version != "go1.22.5" {
		t.Fatalf("%s %s", name, got.ReportMD.Version)
	}
	if got.Applicability != task.NotApplicable || !strings.Contains(got.Verdict, "исправление уже полностью есть в стандартной библиотеке Go go1.22.5") {
		t.Fatalf("%s %s %+v", got.Applicability, got.Verdict, got.ReportMD.PatchCheck)
	}
}

func TestStdlibPartialPatchNote(t *testing.T) {
	goroot := t.TempDir()
	mustWrite(t, filepath.Join(goroot, "src", "crypto", "tls", "host_id.go"), hostBody("fixed"))
	mustWrite(t, filepath.Join(goroot, "src", "crypto", "tls", "other.go"), hostBody("vuln"))
	stubLookup(t, func(context.Context, string, string) (string, error) { return goroot, nil })
	stubList(t, func(context.Context, string, bool) (map[string]struct{}, error) {
		return map[string]struct{}{"crypto/tls": {}}, nil
	})
	restore := stubModuleDeadcode(t, func(context.Context, string, bool) moduleDeadcode {
		return moduleDeadcode{Status: "ok"}
	})
	defer restore()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.22.5\n")
	patch := stdlibFiles{
		appliedHunk("src/crypto/tls/host_id.go", "fixed"),
		appliedHunk("src/crypto/tls/other.go", "fixed"),
		appliedHunk("src/crypto/tls/host_id_test.go", "fixed"),
	}
	got := scanStdlibCase(t, root, patch)
	if got.Applicability != task.Applicable {
		t.Fatal(got.Applicability, got.ReportMD.PreVerdict)
	}
	if !strings.Contains(got.Verdict, "Патч частично применен, но в этих файлах патч не применен - src/crypto/tls/other.go.") {
		t.Fatalf("%s %+v", got.Verdict, got.ReportMD.PatchCheck)
	}
	if strings.Contains(got.Verdict, "_test.go") {
		t.Fatal(got.Verdict)
	}
}

func TestStdlibTwoModules(t *testing.T) {
	goroot := t.TempDir()
	var names []string
	stubLookup(t, func(_ context.Context, dir string, name string) (string, error) {
		names = append(names, name+":"+filepath.Base(dir))
		return goroot, nil
	})
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.22\n")
	mustWrite(t, filepath.Join(root, "sub", "go.mod"), "module example.com/app/sub\n\ngo 1.21.8\n")
	got, err := Scan(context.Background(), Input{
		RepoPath:    root,
		CVEID:       "CVE-2026-1",
		PackageName: "stdlib",
	}, stdlibOneFile("src/crypto/tls/conn.go", "fixed"), staticAI{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || names == nil || len(names) != 1 || names[0] != "go1.21.8:sub" {
		t.Fatalf("%v %+v", names, got)
	}
	if got[0].Applicability != task.Uncertain || got[1].Applicability != task.NotApplicable {
		t.Fatalf("%s %s", got[0].Applicability, got[1].Applicability)
	}
}

func TestStdlibNoGoMod(t *testing.T) {
	stubLookup(t, func(context.Context, string, string) (string, error) {
		t.Fatal("lookup")
		return "", nil
	})
	got := scanStdlibCase(t, t.TempDir(), stdlibOneFile("src/crypto/tls/conn.go", "fixed"))
	if got.Applicability != task.Uncertain || !strings.Contains(got.ReportMD.PreVerdict, "взять неоткуда") {
		t.Fatal(got.Applicability, got.ReportMD.PreVerdict)
	}
}

func TestStdlibMissingFile(t *testing.T) {
	stubLookup(t, func(context.Context, string, string) (string, error) {
		return t.TempDir(), nil
	})
	deadcode := 0
	restore := stubModuleDeadcode(t, func(context.Context, string, bool) moduleDeadcode {
		deadcode++
		return moduleDeadcode{Status: "ok"}
	})
	defer restore()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.22.5\n")
	got := scanStdlibCase(t, root, stdlibOneFile("src/crypto/tls/conn.go", "fixed"))
	if deadcode != 0 || got.Applicability != task.NotApplicable {
		t.Fatal(deadcode, got.Applicability, got.ReportMD.PreVerdict)
	}
	if !strings.Contains(got.ReportMD.PreVerdict, "исходниках не найден") {
		t.Fatal(got.ReportMD.PreVerdict)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func stubLookup(t *testing.T, fn func(context.Context, string, string) (string, error)) {
	t.Helper()
	prev := lookupToolchain
	lookupToolchain = fn
	t.Cleanup(func() { lookupToolchain = prev })
}

func stubList(t *testing.T, fn func(context.Context, string, bool) (map[string]struct{}, error)) {
	t.Helper()
	prev := listModuleDeps
	listModuleDeps = fn
	t.Cleanup(func() { listModuleDeps = prev })
}

func scanStdlibCase(t *testing.T, root string, patches PatchSource) task.ModuleResult {
	t.Helper()
	got, err := Scan(context.Background(), Input{
		RepoPath:     root,
		ComponentURL: "https://github.com/acme/app.git",
		CVEID:        "CVE-2026-1",
		PackageName:  "stdlib",
	}, patches, staticAI{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("%d", len(got))
	}
	return got[0]
}

func stdlibOneFile(name, body string) PatchSource {
	return stdlibFiles{appliedHunk(name, body)}
}

type stdlibFiles []task.PatchFile

func (f stdlibFiles) Fetch(context.Context, string) (task.CVEPatch, error) {
	return task.CVEPatch{CVE: "CVE-2026-1", Files: []task.PatchFile(f)}, nil
}

func writeStdlibFile(t *testing.T, rel, body string) string {
	t.Helper()
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "src", rel), body)
	return root
}

func hostBody(ret string) string {
	return "package tls\n\nfunc HostID() string {\n\treturn \"" + ret + "\"\n}\n"
}

func TestListDepsWaitsForSlot(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip(err)
	}
	held := holdDeadcodeSlots(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if _, err := runListDeps(ctx, t.TempDir(), false); err == nil {
		t.Fatal("go list took a slot while both were busy")
	}
	releaseDeadcode()
	*held--
}

func TestToolchainLookupDoesNotTakeSlot(t *testing.T) {
	held := holdDeadcodeSlots(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	goroot, err := runLookupToolchain(ctx, t.TempDir(), "go1.22.2")
	if err != nil {
		t.Fatal(err)
	}
	if goroot == "" {
		t.Fatal("empty GOROOT")
	}
	releaseDeadcode()
	*held--
}
