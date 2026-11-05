package scan

import (
	"path/filepath"
	"strings"
	"testing"

	"cve-patch-viewer/internal/applicability/task"
)

func TestPatchFullyAppliedRequiresEveryHunk(t *testing.T) {
	root := t.TempDir()
	rel := "pkg/id.go"
	mustWrite(t, filepath.Join(root, rel), "func HostID() string {\n\treturn \"fixed\"\n}\n")
	file := task.PatchFile{Filename: rel, Patch: "" +
		"@@ -1,3 +1,3 @@\n" +
		" func HostID() string {\n" +
		"-\treturn \"vuln\"\n" +
		"+\treturn \"fixed\"\n" +
		" }\n"}
	match := []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}
	if !patchFullyApplied(root, []task.PatchFile{file}, match) {
		t.Fatal("fixed file should count as applied")
	}

	mustWrite(t, filepath.Join(root, rel), "func HostID() string {\n\treturn \"vuln\"\n}\n")
	if patchFullyApplied(root, []task.PatchFile{file}, match) {
		t.Fatal("old code must stay applicable")
	}

	mustWrite(t, filepath.Join(root, rel), "func Other() string {\n\treturn \"old\"\n}\nfunc Other() string {\n\treturn \"fixed\"\n}\n")
	fileBoth := task.PatchFile{Filename: rel, Patch: "" +
		"@@ -1,3 +1,3 @@\n" +
		" func Other() string {\n" +
		"-\treturn \"old\"\n" +
		"+\treturn \"fixed\"\n" +
		" }\n"}
	if patchFullyApplied(root, []task.PatchFile{fileBoth}, match) {
		t.Fatal("old lines outside the new block must block a full match")
	}
}

func TestPatchAppliedOnlyWhenReachable(t *testing.T) {
	root := t.TempDir()
	rel := "pkg/id.go"
	mustWrite(t, filepath.Join(root, rel), "func HostID() string {\n\treturn \"fixed\"\n}\n")
	files := []task.PatchFile{{Filename: rel, Patch: "" +
		"@@ -1,3 +1,3 @@\n" +
		" func HostID() string {\n" +
		"-\treturn \"vuln\"\n" +
		"+\treturn \"fixed\"\n" +
		" }\n"}}
	report := task.Report{PatchFiles: []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}}
	if note := noteAppliedPatch(root, files, &report); note != "" || report.PatchApplied != nil {
		t.Fatal("unreachable patch must stay applicable")
	}
	if report.PatchCheck == nil || report.PatchCheck.Ran || !strings.Contains(report.PatchCheck.Section(), "не проводилась") {
		t.Fatalf("%+v", report.PatchCheck)
	}
	report.Narrative = "журнал анализа"
	if !strings.Contains(report.PublicText(), "Проверка применения патча") || !strings.Contains(report.PublicText(), "журнал анализа") {
		t.Fatal(report.PublicText())
	}
	yes := true
	report.Reach = &task.ReachReport{Reachable: &yes}
	if note := noteAppliedPatch(root, files, &report); note == "" || report.PatchApplied == nil || !report.PatchApplied.Applied {
		t.Fatal(note, report.PatchApplied)
	}
	if decideApplicability(report, "") != task.NotApplicable {
		t.Fatal(decideApplicability(report, ""))
	}
	if report.PatchCheck == nil || report.PatchCheck.Outcome != task.PatchCheckFull || !strings.Contains(report.PatchCheck.Section(), "неприменима") {
		t.Fatal(report.PatchCheck.Section())
	}

	report.Reach = &task.ReachReport{Reachable: &yes}
	report.PatchApplied = nil
	mustWrite(t, filepath.Join(root, rel), "func HostID() string {\n\treturn \"vuln\"\n}\n")
	if note := noteAppliedPatch(root, files, &report); note != "" || report.PatchApplied != nil {
		t.Fatal("partial patch must stay applicable")
	}
	if report.PatchCheck.Outcome != task.PatchCheckPartial || !strings.Contains(report.PatchCheck.Section(), "не целиком") {
		t.Fatal(report.PatchCheck.Section())
	}
}

func TestDeletedFileCountsOnlyWhenGone(t *testing.T) {
	root := t.TempDir()
	diff := "--- a/old.go\n+++ /dev/null\n@@ -1 +0,0 @@\n-package old\n"
	if !patchFullyApplied(root, []task.PatchFile{{Filename: "old.go", Patch: diff}}, []task.PatchFileMatch{{Filename: "old.go", Found: false}}) {
		t.Fatal("missing deleted file is applied")
	}
	mustWrite(t, filepath.Join(root, "old.go"), "package old\n")
	if patchFullyApplied(root, []task.PatchFile{{Filename: "old.go", Patch: diff}}, []task.PatchFileMatch{{Filename: "old.go", Found: true, Path: "./old.go"}}) {
		t.Fatal("deleted file still present")
	}
}
