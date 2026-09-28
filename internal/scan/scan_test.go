package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanKeepsOnlyGoModThatListsPackage(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/root\n\nrequire github.com/foo/bar v1.2.3\n")
	mustWrite(t, filepath.Join(root, "sub", "go.mod"), "module example.com/sub\n\nrequire github.com/other/pkg v0.1.0\n")
	mustWrite(t, filepath.Join(root, "tools", "go.mod"), "module example.com/tools\n\nrequire github.com/foo/bar v1.2.3\n")
	mustWrite(t, filepath.Join(root, ".git", "go.mod"), "require github.com/foo/bar v1.2.3\n")

	got, err := Scan(context.Background(), Input{
		RepoPath:     root,
		ComponentURL: "https://example.com/repo",
		Branch:       "main",
		CVEID:        "CVE-2024-1",
		PackageName:  "github.com/foo/bar",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d results: %+v", len(got), got)
	}
	if got[0].GoModPath != "./go.mod" || got[1].GoModPath != "./tools/go.mod" {
		t.Fatalf("%+v", got)
	}
	if !strings.Contains(got[0].Verdict, "github.com/foo/bar listed in ./go.mod") {
		t.Fatal(got[0].Verdict)
	}
	if !strings.Contains(got[0].ReportMD, "require github.com/foo/bar v1.2.3") {
		t.Fatal(got[0].ReportMD)
	}
	for _, m := range got {
		if strings.Contains(m.GoModPath, ".git") || strings.Contains(m.ReportMD, "example.com/sub") {
			t.Fatalf("unexpected module: %+v", m)
		}
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
