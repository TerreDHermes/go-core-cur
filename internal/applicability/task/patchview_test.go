package task

import "testing"

func TestVisiblePatchFilesUsesRepoPathThenCardPath(t *testing.T) {
	modules := []ModuleResult{
		{ReportMD: Report{
			Patch: CVEPatch{Files: []PatchFile{
				{Filename: "src/net/http/server.go", Patch: "diff-server"},
				{Filename: "README.md", Patch: "   "},
				{Filename: "missing.go", Patch: "diff-missing"},
			}},
			PatchFiles: []PatchFileMatch{
				{Filename: "src/net/http/server.go", Found: true, Path: "./vendor/golang.org/x/net/http/server.go"},
				{Filename: "missing.go", Found: false},
			},
		}},
		{ReportMD: Report{
			Patch: CVEPatch{Files: []PatchFile{
				{Filename: "src/net/http/server.go", Patch: "other"},
				{Filename: "only-later.go", Patch: "diff-later"},
			}},
			PatchFiles: []PatchFileMatch{
				{Filename: "src/net/http/server.go", Found: true, Path: "./other/server.go"},
				{Filename: "only-later.go", Found: true, Path: "./pkg/only-later.go"},
			},
		}},
		{ReportMD: Report{
			Patch: CVEPatch{Files: []PatchFile{
				{Filename: "src/crypto/tls/conn.go", Patch: "diff-tls"},
			}},
			PatchFiles: []PatchFileMatch{
				{Filename: "src/crypto/tls/conn.go", Found: true, Path: "/tmp/go/src/crypto/tls/conn.go"},
			},
		}},
	}
	got := VisiblePatchFiles(modules)
	want := []PatchFileView{
		{Path: "vendor/golang.org/x/net/http/server.go", Patch: "diff-server"},
		{Path: "missing.go", Patch: "diff-missing"},
		{Path: "pkg/only-later.go", Patch: "diff-later"},
		{Path: "src/crypto/tls/conn.go", Patch: "diff-tls"},
	}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%d %+v", i, got[i])
		}
	}
	if got := VisiblePatchFiles(nil); len(got) != 0 {
		t.Fatal(got)
	}
}
