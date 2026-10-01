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
	cve string
}

func (f fakePatch) Fetch(context.Context, string) (task.CVEPatch, error) {
	return task.CVEPatch{CVE: f.cve, Files: []task.PatchFile{{Filename: "a.go", Patch: "diff"}}}, nil
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
	if !strings.Contains(got[0].Verdict, "./vendor/github.com/foo/bar/a.go") {
		t.Fatal(got[0].Verdict)
	}
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
