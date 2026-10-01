package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cveanalysis/internal/task"
)

func TestScanKeepsOnlyGoModThatListsPackage(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/root\n\nrequire github.com/foo/bar v1.2.3\n")
	mustWrite(t, filepath.Join(root, "sub", "go.mod"), "module example.com/sub\n\nrequire github.com/other/pkg v0.1.0\n")
	mustWrite(t, filepath.Join(root, "tools", "go.mod"), "module example.com/tools\n\nrequire github.com/foo/bar v1.2.3\n")
	mustWrite(t, filepath.Join(root, ".git", "go.mod"), "require github.com/foo/bar v1.2.3\n")
	if err := os.MkdirAll(filepath.Join(root, "vendor"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := Scan(context.Background(), Input{
		RepoPath:     root,
		ComponentURL: "https://example.com/repo",
		Branch:       "main",
		CVEID:        "CVE-2024-1",
		PackageName:  "github.com/foo/bar",
	}, fakePatch{cve: "CVE-2024-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d results: %+v", len(got), got)
	}
	if got[0].GoModPath != "./go.mod" || got[1].GoModPath != "./tools/go.mod" {
		t.Fatalf("%+v", got)
	}
	if got[0].ReportMD.Stage != task.StagePatchFiles || !strings.Contains(got[0].Verdict, "Ни один файл патча в vendor не найден") {
		t.Fatal(got[0].Verdict)
	}
	if len(got[0].ReportMD.PatchFiles) != 1 || got[0].ReportMD.PatchFiles[0].Found || got[0].ReportMD.PatchFiles[0].Filename != "a.go" {
		t.Fatalf("%+v", got[0].ReportMD.PatchFiles)
	}
	if got[1].ReportMD.Stage != task.StageNoVendor || !strings.Contains(got[1].Verdict, "без vendor анализ невозможен") {
		t.Fatal(got[1].Verdict)
	}
	if len(got[0].ReportMD.MatchingLines) != 1 || !strings.Contains(got[0].ReportMD.MatchingLines[0], "github.com/foo/bar") {
		t.Fatal(got[0].ReportMD.MatchingLines)
	}
	if !got[0].ReportMD.HasVendor || got[0].ReportMD.VendorPath != "./vendor" {
		t.Fatalf("root vendor: %+v", got[0].ReportMD)
	}
	if got[1].ReportMD.HasVendor {
		t.Fatalf("tools should not have vendor: %+v", got[1].ReportMD)
	}
	if got[0].ReportMD.Patch.CVE != "CVE-2024-1" || !strings.Contains(got[0].ReportMD.Markdown(), "Vendor: yes") {
		t.Fatal(got[0].ReportMD.Markdown())
	}
	for _, m := range got {
		if strings.Contains(m.GoModPath, ".git") {
			t.Fatalf("unexpected module: %+v", m)
		}
	}
}

type fakePatch struct {
	cve   string
	files []task.PatchFile
}

func (f fakePatch) Fetch(context.Context, string) (task.CVEPatch, error) {
	files := f.files
	if files == nil {
		files = []task.PatchFile{{Filename: "a.go", Patch: "diff"}}
	}
	return task.CVEPatch{CVE: f.cve, Files: files}, nil
}

func TestScanStopsWhenRepositoryIsNotGo(t *testing.T) {
	got, err := Scan(context.Background(), Input{RepoPath: t.TempDir(), PackageName: "pkg"}, fakePatch{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ReportMD.Stage != task.StageNotGo {
		t.Fatalf("%+v", got)
	}
}

func TestScanFindsPatchedFileInVendor(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/root\n\nrequire github.com/foo/bar v1.2.3\n")
	mustWrite(t, filepath.Join(root, "vendor", "github.com", "foo", "bar", "a.go"), "package bar\n")

	got, err := Scan(context.Background(), Input{
		RepoPath:    root,
		CVEID:       "CVE-2024-1",
		PackageName: "github.com/foo/bar",
	}, fakePatch{cve: "CVE-2024-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].ReportMD.FoundPatchFiles) != 1 {
		t.Fatalf("%+v", got)
	}
	if got[0].ReportMD.FoundPatchFiles[0] != "./vendor/github.com/foo/bar/a.go" {
		t.Fatal(got[0].ReportMD.FoundPatchFiles)
	}
	if len(got[0].ReportMD.PatchFiles) != 1 || !got[0].ReportMD.PatchFiles[0].Found {
		t.Fatal(got[0].ReportMD.PatchFiles)
	}
	if !strings.Contains(got[0].Verdict, "./vendor/github.com/foo/bar/a.go") {
		t.Fatal(got[0].Verdict)
	}
	if !strings.Contains(got[0].ReportMD.Markdown(), "`a.go`: true") {
		t.Fatal(got[0].ReportMD.Markdown())
	}
}

func TestScanStripsNestedModulePrefix(t *testing.T) {
	root := t.TempDir()
	const modulePath = "go.opentelemetry.io/otel/sdk"
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/alertmanager\n\nrequire "+modulePath+" v1.43.0\n")
	mustWrite(t, filepath.Join(root, "vendor", "go.opentelemetry.io", "otel", "sdk", "resource", "host_id.go"), "package resource\n")

	got := scanOne(t, root, modulePath, []task.PatchFile{
		{Filename: "sdk/resource/host_id.go", Patch: "diff"},
		{Filename: "sdk/resource/missing.go", Patch: "diff"},
	})
	if got.ReportMD.PatchFiles[0].Found != true || got.ReportMD.PatchFiles[0].Path != "./vendor/go.opentelemetry.io/otel/sdk/resource/host_id.go" {
		t.Fatal(got.ReportMD.PatchFiles[0])
	}
	if got.ReportMD.PatchFiles[1].Found || got.ReportMD.PatchFiles[1].Path != "" {
		t.Fatal(got.ReportMD.PatchFiles[1])
	}
	if len(got.ReportMD.FoundPatchFiles) != 1 {
		t.Fatal(got.ReportMD.FoundPatchFiles)
	}
	if strings.Contains(got.ReportMD.FoundPatchFiles[0], "/sdk/sdk/") {
		t.Fatal(got.ReportMD.FoundPatchFiles[0])
	}
}

func TestScanKeepsLiteralPathWhenBothCandidatesExist(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/root\n\nrequire github.com/foo/bar v1.2.3\n")
	mustWrite(t, filepath.Join(root, "vendor", "github.com", "foo", "bar", "bar", "baz.go"), "package bar\n")
	mustWrite(t, filepath.Join(root, "vendor", "github.com", "foo", "bar", "baz.go"), "package bar\n")

	got := scanOne(t, root, "github.com/foo/bar", []task.PatchFile{{Filename: "bar/baz.go"}})
	if !got.ReportMD.PatchFiles[0].Found || got.ReportMD.PatchFiles[0].Path != "./vendor/github.com/foo/bar/bar/baz.go" {
		t.Fatal(got.ReportMD.PatchFiles[0])
	}
}

func TestScanFindsModulePathEmbeddedInPatch(t *testing.T) {
	root := t.TempDir()
	const modulePath = "k8s.io/client-go"
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/root\n\nrequire "+modulePath+" v0.29.0\n")
	mustWrite(t, filepath.Join(root, "vendor", "k8s.io", "client-go", "rest", "config.go"), "package rest\n")

	got := scanOne(t, root, modulePath, []task.PatchFile{{Filename: "staging/src/k8s.io/client-go/rest/config.go"}})
	if !got.ReportMD.PatchFiles[0].Found || got.ReportMD.PatchFiles[0].Path != "./vendor/k8s.io/client-go/rest/config.go" {
		t.Fatal(got.ReportMD.PatchFiles[0])
	}
}

func TestScanRootReadsRepositoryRoot(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/otel\n")
	mustWrite(t, filepath.Join(root, "sdk", "resource", "host_id.go"), "package resource\n")
	mustWrite(t, filepath.Join(root, "vendor", "go.opentelemetry.io", "otel", "sdk", "resource", "host_id.go"), "package resource\n")

	got, err := Scan(context.Background(), Input{
		RepoPath:    root,
		CVEID:       "CVE-2026-24051",
		PackageName: "root",
	}, fakePatch{files: []task.PatchFile{
		{Filename: "sdk/resource/host_id.go"},
		{Filename: "sdk/resource/missing.go"},
		{Filename: "../secret.go"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].GoModPath != "." || !got[0].ReportMD.FromRoot {
		t.Fatalf("%+v", got)
	}
	files := got[0].ReportMD.PatchFiles
	if len(files) != 3 || !files[0].Found || files[0].Path != "./sdk/resource/host_id.go" {
		t.Fatal(files)
	}
	if files[1].Found || files[2].Found {
		t.Fatal(files)
	}
	if !strings.Contains(got[0].Verdict, "go.mod не искался") || !strings.Contains(got[0].Verdict, "./sdk/resource/host_id.go") {
		t.Fatal(got[0].Verdict)
	}
	if strings.Contains(got[0].Verdict, "vendor") {
		t.Fatal(got[0].Verdict)
	}
	if !strings.Contains(got[0].ReportMD.Markdown(), "`sdk/resource/missing.go`: false") {
		t.Fatal(got[0].ReportMD.Markdown())
	}
}

func TestScanRootWithoutGoMod(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.txt"), "not go\n")
	got, err := Scan(context.Background(), Input{RepoPath: root, PackageName: "root"}, fakePatch{files: []task.PatchFile{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ReportMD.Stage != task.StageNoPatch || !strings.Contains(got[0].Verdict, "патч не найден") {
		t.Fatalf("%+v", got[0])
	}
}

func TestScanRootAllMissing(t *testing.T) {
	root := t.TempDir()
	got, err := Scan(context.Background(), Input{RepoPath: root, PackageName: "root"}, fakePatch{files: []task.PatchFile{{Filename: "a.go"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ReportMD.PatchFiles[0].Found || len(got[0].ReportMD.FoundPatchFiles) != 0 {
		t.Fatal(got[0].ReportMD)
	}
	if !strings.Contains(got[0].Verdict, "Ни один файл патча в корне не найден") {
		t.Fatal(got[0].Verdict)
	}
}

func scanOne(t *testing.T, root, pkg string, files []task.PatchFile) task.ModuleResult {
	t.Helper()
	got, err := Scan(context.Background(), Input{
		RepoPath:    root,
		CVEID:       "CVE-2026-24051",
		PackageName: pkg,
	}, fakePatch{cve: "CVE-2026-24051", files: files})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	return got[0]
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
