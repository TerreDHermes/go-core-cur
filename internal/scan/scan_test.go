package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanFindsGoMod(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/root\n")
	mustWrite(t, filepath.Join(root, "sub", "go.mod"), "module example.com/sub\n")
	mustWrite(t, filepath.Join(root, ".git", "go.mod"), "ignored\n")
	mustWrite(t, filepath.Join(root, "README.md"), "nope\n")

	res, err := Scan(context.Background(), Input{
		RepoPath:     root,
		ComponentURL: "https://example.com/repo",
		Branch:       "main",
		CVEID:        "CVE-2024-1",
		PackageName:  "example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != "found 2 go.mod" {
		t.Fatalf("verdict %q", res.Verdict)
	}
	if !strings.Contains(res.ReportMD, "./go.mod\n") || !strings.Contains(res.ReportMD, "./sub/go.mod\n") {
		t.Fatalf("report:\n%s", res.ReportMD)
	}
	if strings.Contains(res.ReportMD, ".git") {
		t.Fatalf("git dir leaked:\n%s", res.ReportMD)
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
