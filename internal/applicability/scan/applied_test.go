package scan

import (
	"context"
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

func TestMarkdownDoesNotBlockAFullPatch(t *testing.T) {
	root := t.TempDir()
	rel := "pkg/id.go"
	mustWrite(t, filepath.Join(root, rel), "func HostID() string {\n\treturn \"fixed\"\n}\n")
	mustWrite(t, filepath.Join(root, "CHANGELOG.md"), "unrelated\n")
	code := task.PatchFile{Filename: rel, Patch: "" +
		"@@ -1,3 +1,3 @@\n" +
		" func HostID() string {\n" +
		"-\treturn \"vuln\"\n" +
		"+\treturn \"fixed\"\n" +
		" }\n"}
	md := task.PatchFile{Filename: "CHANGELOG.MD", Patch: "" +
		"@@ -1 +1 @@\n" +
		"-old changelog\n" +
		"+new changelog\n"}
	matches := []task.PatchFileMatch{
		{Filename: rel, Found: true, Path: "./" + rel},
		{Filename: "CHANGELOG.MD", Found: true, Path: "./CHANGELOG.md"},
	}
	if !patchFullyApplied(root, []task.PatchFile{code, md}, matches) {
		t.Fatal("changelog must not keep an otherwise applied patch open")
	}
	yes := true
	report := task.Report{PatchFiles: matches, Reach: &task.ReachReport{Reachable: &yes}}
	if note := noteAppliedPatch(root, []task.PatchFile{code, md}, &report); note == "" || report.PatchApplied == nil || !report.PatchApplied.Applied {
		t.Fatal(note, report.PatchCheck)
	}
	if report.PatchCheck.Outcome != task.PatchCheckFull || !strings.Contains(report.PatchCheck.Section(), "markdown") {
		t.Fatal(report.PatchCheck.Section())
	}
	if decideApplicability(report, "") != task.NotApplicable {
		t.Fatal(decideApplicability(report, ""))
	}
}

func TestMarkdownOnlyPatchDoesNotCountAsApplied(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "CHANGELOG.md"), "new changelog\n")
	md := task.PatchFile{Filename: "docs/CHANGELOG.md", Patch: "" +
		"@@ -1 +1 @@\n" +
		"-old changelog\n" +
		"+new changelog\n"}
	matches := []task.PatchFileMatch{{Filename: "docs/CHANGELOG.md", Found: true, Path: "./CHANGELOG.md"}}
	if patchFullyApplied(root, []task.PatchFile{md}, matches) {
		t.Fatal("a markdown-only patch is not a code fix")
	}
	report := task.Report{PatchFiles: matches}
	if note := noteAppliedPatch(root, []task.PatchFile{md}, &report); note != "" || report.PatchApplied != nil {
		t.Fatal(note, report.PatchApplied)
	}
	if report.PatchCheck == nil || report.PatchCheck.Ran || report.PatchCheck.Outcome != task.PatchCheckNotRun {
		t.Fatalf("%+v", report.PatchCheck)
	}
	if !strings.Contains(report.PatchCheck.Section(), "только markdown") {
		t.Fatal(report.PatchCheck.Section())
	}
	if decideApplicability(report, "") == task.NotApplicable {
		t.Fatal("markdown must not force not applicable")
	}
}

func appliedHunk(name, body string) task.PatchFile {
	return task.PatchFile{Filename: name, Patch: "" +
		"@@ -1,3 +1,3 @@\n" +
		" func HostID() string {\n" +
		"-\treturn \"vuln\"\n" +
		"+\treturn \"" + body + "\"\n" +
		" }\n"}
}

func TestTestFileDoesNotBlockFullPatch(t *testing.T) {
	root := t.TempDir()
	rel := "pkg/id.go"
	mustWrite(t, filepath.Join(root, rel), "func HostID() string {\n\treturn \"fixed\"\n}\n")
	code := appliedHunk(rel, "fixed")
	testFile := appliedHunk("pkg/id_test.go", "fixed")
	matches := []task.PatchFileMatch{
		{Filename: rel, Found: true, Path: "./" + rel},
		{Filename: "pkg/id_test.go", Found: false},
	}
	if !patchFullyApplied(root, []task.PatchFile{code, testFile}, matches) {
		t.Fatal("a missing test file must not keep the patch open")
	}
	yes := true
	report := task.Report{PatchFiles: matches, Reach: &task.ReachReport{Reachable: &yes}}
	if note := noteAppliedPatch(root, []task.PatchFile{code, testFile}, &report); note == "" || report.PatchApplied == nil || !report.PatchApplied.Applied {
		t.Fatal(note, report.PatchCheck)
	}
	if report.PatchCheck.Outcome != task.PatchCheckFull || len(report.PatchCheck.NotApplied) != 0 {
		t.Fatalf("%+v", report.PatchCheck)
	}
	if !strings.Contains(report.PatchCheck.Section(), "Тестовые файлы") {
		t.Fatal(report.PatchCheck.Section())
	}
}

func TestPartialPatchNamesOnlyUnappliedCodeFiles(t *testing.T) {
	root := t.TempDir()
	fixedRel := "pkg/id.go"
	openRel := "pkg/other.go"
	mustWrite(t, filepath.Join(root, fixedRel), "func HostID() string {\n\treturn \"fixed\"\n}\n")
	mustWrite(t, filepath.Join(root, openRel), "func HostID() string {\n\treturn \"vuln\"\n}\n")
	files := []task.PatchFile{
		appliedHunk(fixedRel, "fixed"),
		appliedHunk(openRel, "fixed"),
		appliedHunk("pkg/other_test.go", "fixed"),
	}
	matches := []task.PatchFileMatch{
		{Filename: fixedRel, Found: true, Path: "./" + fixedRel},
		{Filename: openRel, Found: true, Path: "./" + openRel},
		{Filename: "pkg/other_test.go", Found: false},
	}
	yes := true
	report := task.Report{PatchFiles: matches, Reach: &task.ReachReport{Reachable: &yes}}
	if note := noteAppliedPatch(root, files, &report); note != "" || report.PatchApplied != nil {
		t.Fatal(note, report.PatchApplied)
	}
	if report.PatchCheck.Outcome != task.PatchCheckPartial {
		t.Fatal(report.PatchCheck.Outcome)
	}
	if strings.Join(report.PatchCheck.NotApplied, ",") != openRel {
		t.Fatal(report.PatchCheck.NotApplied)
	}
	got := withPartialPatchNote("Уязвимость применима к компоненту.", report)
	want := "Уязвимость применима к компоненту. Патч частично применен, но в этих файлах патч не применен - pkg/other.go."
	if got != want {
		t.Fatal(got)
	}
	if strings.Contains(got, "other_test.go") {
		t.Fatal(got)
	}
}

func TestNoAppliedFileSkipsPartialSentence(t *testing.T) {
	root := t.TempDir()
	first := "pkg/id.go"
	second := "pkg/other.go"
	mustWrite(t, filepath.Join(root, first), "func HostID() string {\n\treturn \"vuln\"\n}\n")
	mustWrite(t, filepath.Join(root, second), "func HostID() string {\n\treturn \"vuln\"\n}\n")
	files := []task.PatchFile{appliedHunk(first, "fixed"), appliedHunk(second, "fixed")}
	matches := []task.PatchFileMatch{
		{Filename: first, Found: true, Path: "./" + first},
		{Filename: second, Found: true, Path: "./" + second},
	}
	yes := true
	report := task.Report{PatchFiles: matches, Reach: &task.ReachReport{Reachable: &yes}}
	noteAppliedPatch(root, files, &report)
	if report.PatchCheck.Outcome != task.PatchCheckPartial || len(report.PatchCheck.NotApplied) != 0 {
		t.Fatalf("%+v", report.PatchCheck)
	}
	if got := withPartialPatchNote("Уязвимость применима.", report); got != "Уязвимость применима." {
		t.Fatal(got)
	}
}

func TestPartialNoteReachesTheVerdict(t *testing.T) {
	restore := stubModuleDeadcode(t, func(context.Context, string, bool) moduleDeadcode {
		return moduleDeadcode{Status: "ok"}
	})
	defer restore()

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/alertmanager\n\nrequire go.opentelemetry.io/otel/sdk v1.43.0\n")
	fixed := "vendor/go.opentelemetry.io/otel/sdk/resource/host_id.go"
	open := "vendor/go.opentelemetry.io/otel/sdk/resource/other.go"
	mustWrite(t, filepath.Join(root, fixed), "package resource\n\nfunc HostID() string {\n\treturn \"fixed\"\n}\n")
	mustWrite(t, filepath.Join(root, open), "package resource\n\nfunc HostID() string {\n\treturn \"vuln\"\n}\n")
	got, err := Scan(context.Background(), Input{
		RepoPath:    root,
		CVEID:       "CVE-2026-24051",
		PackageName: "go.opentelemetry.io/otel/sdk",
	}, twoFilePatch{}, staticAI{})
	if err != nil {
		t.Fatal(err)
	}
	verdict := got[0].Verdict
	if !strings.Contains(verdict, "Патч частично применен, но в этих файлах патч не применен - sdk/resource/other.go.") {
		t.Fatal(verdict)
	}
	if strings.Contains(verdict, "_test.go") {
		t.Fatal(verdict)
	}
	if got[0].Applicability != task.Applicable {
		t.Fatal(got[0].Applicability)
	}
}

type twoFilePatch struct{}

func (twoFilePatch) Fetch(context.Context, string) (task.CVEPatch, error) {
	return task.CVEPatch{
		CVE: "CVE-2026-24051",
		Files: []task.PatchFile{
			appliedHunk("sdk/resource/host_id.go", "fixed"),
			appliedHunk("sdk/resource/other.go", "fixed"),
			appliedHunk("sdk/resource/host_id_test.go", "fixed"),
		},
	}, nil
}

func TestTestOnlyPatchIsNotApplied(t *testing.T) {
	root := t.TempDir()
	file := appliedHunk("pkg/id_test.go", "fixed")
	matches := []task.PatchFileMatch{{Filename: file.Filename, Found: true, Path: "./pkg/id_test.go"}}
	mustWrite(t, filepath.Join(root, "pkg/id_test.go"), "func HostID() string {\n\treturn \"fixed\"\n}\n")
	if patchFullyApplied(root, []task.PatchFile{file}, matches) {
		t.Fatal("tests alone are not a code fix")
	}
	report := task.Report{PatchFiles: matches}
	if note := noteAppliedPatch(root, []task.PatchFile{file}, &report); note != "" || report.PatchApplied != nil {
		t.Fatal(note)
	}
	if report.PatchCheck.Ran || report.PatchCheck.Outcome != task.PatchCheckNotRun {
		t.Fatalf("%+v", report.PatchCheck)
	}
}
