package scan

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"cve-patch-viewer/internal/applicability/task"
)

func TestMeaningConfirmsADriftedAddition(t *testing.T) {
	root := t.TempDir()
	rel := "pkg/id.go"
	mustWrite(t, filepath.Join(root, rel), driftedBody("addedUniqueCall()"))
	file := driftedHunk(rel, "addedUniqueCall()")
	matches := []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}
	if status, line := assessPatchFile(root, file, matches); status != "partial" {
		t.Fatal(status, line)
	}
	ai := &meaningAI{reply: func(prompt string) (string, error) {
		if strings.Contains(prompt, "совпали") || strings.Contains(prompt, "не применен") || strings.Contains(prompt, "применима") {
			t.Fatalf("prompt carries the line-check verdict:\n%s", prompt)
		}
		if !strings.Contains(prompt, "Файл: "+rel) || !strings.Contains(prompt, "addedUniqueCall()") {
			t.Fatalf("prompt:\n%s", prompt)
		}
		if !strings.Contains(prompt, "func Foo()") {
			t.Fatalf("function body missing:\n%s", prompt)
		}
		return "1: да | addedUniqueCall()", nil
	}}
	yes := true
	report := task.Report{PatchFiles: matches, Reach: &task.ReachReport{Reachable: &yes}}
	note := noteAppliedPatchReviewed(context.Background(), ai, root, []task.PatchFile{file}, &report)
	if len(ai.prompts) != 1 {
		t.Fatal(len(ai.prompts))
	}
	if note == "" || report.PatchApplied == nil || !report.PatchApplied.Applied {
		t.Fatal(note, report.PatchApplied)
	}
	if report.PatchCheck.Outcome != task.PatchCheckFull || len(report.PatchCheck.NotApplied) != 0 {
		t.Fatalf("%+v", report.PatchCheck)
	}
	if !strings.Contains(report.PatchCheck.Section(), "смысловой сверкой") {
		t.Fatal(report.PatchCheck.Section())
	}
}

func TestMeaningRejectsAQuoteOutsideTheExcerpt(t *testing.T) {
	root := t.TempDir()
	rel := "pkg/id.go"
	mustWrite(t, filepath.Join(root, rel), driftedBody("addedUniqueCall()"))
	file := driftedHunk(rel, "addedUniqueCall()")
	matches := []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}
	yes := true
	report := task.Report{PatchFiles: matches, Reach: &task.ReachReport{Reachable: &yes}}

	for _, reply := range []string{
		"1: да | notInThisFile()",
		"1: да | contextLine()",
		"1: нет",
		"не знаю",
	} {
		ai := &meaningAI{reply: func(string) (string, error) { return reply, nil }}
		report.PatchApplied = &task.PatchApplied{Applied: true}
		note := noteAppliedPatchReviewed(context.Background(), ai, root, []task.PatchFile{file}, &report)
		if note != "" || report.PatchApplied != nil || report.PatchCheck.Outcome != task.PatchCheckPartial {
			t.Fatalf("reply %q: %s %+v", reply, note, report.PatchCheck)
		}
	}
}

func TestMeaningAsksOncePerOpenFile(t *testing.T) {
	root := t.TempDir()
	first := "pkg/a.go"
	second := "pkg/b.go"
	mustWrite(t, filepath.Join(root, first), driftedBody("firstUniqueCall()"))
	mustWrite(t, filepath.Join(root, second), driftedBody("secondUniqueCall()"))
	files := []task.PatchFile{driftedHunk(first, "firstUniqueCall()"), driftedHunk(second, "secondUniqueCall()")}
	matches := []task.PatchFileMatch{
		{Filename: first, Found: true, Path: "./" + first},
		{Filename: second, Found: true, Path: "./" + second},
	}
	ai := &meaningAI{reply: func(prompt string) (string, error) {
		switch {
		case strings.Contains(prompt, "Файл: "+first):
			if strings.Contains(prompt, "secondUniqueCall()") {
				t.Fatal(prompt)
			}
			return "1: да | firstUniqueCall()", nil
		case strings.Contains(prompt, "Файл: "+second):
			if strings.Contains(prompt, "firstUniqueCall()") {
				t.Fatal(prompt)
			}
			return "1: нет", nil
		default:
			t.Fatal(prompt)
			return "", nil
		}
	}}
	yes := true
	report := task.Report{PatchFiles: matches, Reach: &task.ReachReport{Reachable: &yes}}
	note := noteAppliedPatchReviewed(context.Background(), ai, root, files, &report)
	if len(ai.prompts) != 2 {
		t.Fatal(len(ai.prompts))
	}
	if note != "" || report.PatchApplied != nil || report.PatchCheck.Outcome != task.PatchCheckPartial {
		t.Fatal(note, report.PatchCheck)
	}
	if strings.Join(report.PatchCheck.NotApplied, ",") != second {
		t.Fatal(report.PatchCheck.NotApplied)
	}
}

func TestMeaningSkipsAFullFileAndAPureDeletion(t *testing.T) {
	root := t.TempDir()
	openRel := "pkg/open.go"
	doneRel := "pkg/done.go"
	mustWrite(t, filepath.Join(root, openRel), "package p\n\nfunc Foo() {\n\tcontextLine()\n\tremovedUnique()\n\tmore()\n}\n")
	mustWrite(t, filepath.Join(root, doneRel), "package p\n\nfunc Foo() {\n\tcontextLine()\n\taddedUniqueCall()\n\tmore()\n}\n")
	files := []task.PatchFile{
		{Filename: openRel, Patch: "" +
			"@@ func Foo\n" +
			" contextLine()\n" +
			"-removedUnique()\n" +
			" more()\n"},
		driftedHunk(doneRel, "addedUniqueCall()"),
	}
	matches := []task.PatchFileMatch{
		{Filename: openRel, Found: true, Path: "./" + openRel},
		{Filename: doneRel, Found: true, Path: "./" + doneRel},
	}
	if status, line := assessPatchFile(root, files[1], matches); status != "full" {
		t.Fatal(status, line)
	}
	ai := &meaningAI{reply: func(prompt string) (string, error) {
		t.Fatal(prompt)
		return "", nil
	}}
	yes := true
	report := task.Report{PatchFiles: matches, Reach: &task.ReachReport{Reachable: &yes}}
	note := noteAppliedPatchReviewed(context.Background(), ai, root, files, &report)
	if len(ai.prompts) != 0 {
		t.Fatal(ai.prompts)
	}
	if note != "" || report.PatchCheck.Outcome != task.PatchCheckPartial {
		t.Fatal(note, report.PatchCheck)
	}
	if strings.Contains(strings.Join(report.PatchCheck.Files, "\n"), "Смысловая") {
		t.Fatal(report.PatchCheck.Files)
	}
}

func TestMeaningDoesNotSendAMissingFunction(t *testing.T) {
	root := t.TempDir()
	rel := "pkg/id.go"
	mustWrite(t, filepath.Join(root, rel), driftedBody("addedUniqueCall()"))
	file := task.PatchFile{Filename: rel, Patch: "" +
		"@@ func Gone\n" +
		" contextLine()\n" +
		"+goneUniqueCall()\n" +
		" more()\n" +
		driftedHunk(rel, "addedUniqueCall()").Patch}
	matches := []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}
	ai := &meaningAI{reply: func(prompt string) (string, error) {
		if strings.Contains(prompt, "Gone") || strings.Contains(prompt, "goneUniqueCall") {
			t.Fatal(prompt)
		}
		return "1: да | addedUniqueCall()", nil
	}}
	yes := true
	report := task.Report{PatchFiles: matches, Reach: &task.ReachReport{Reachable: &yes}}
	note := noteAppliedPatchReviewed(context.Background(), ai, root, []task.PatchFile{file}, &report)
	if len(ai.prompts) != 1 || note == "" || report.PatchApplied == nil {
		t.Fatal(len(ai.prompts), note, report.PatchCheck)
	}
}

func TestMeaningKeepsTheLineCheckWhenTheModelFails(t *testing.T) {
	root := t.TempDir()
	rel := "pkg/id.go"
	mustWrite(t, filepath.Join(root, rel), driftedBody("addedUniqueCall()"))
	file := driftedHunk(rel, "addedUniqueCall()")
	matches := []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}
	ai := &meaningAI{reply: func(string) (string, error) { return "", fmt.Errorf("down") }}
	yes := true
	report := task.Report{PatchFiles: matches, Reach: &task.ReachReport{Reachable: &yes}}
	note := noteAppliedPatchReviewed(context.Background(), ai, root, []task.PatchFile{file}, &report)
	if note != "" || report.PatchApplied != nil || report.PatchCheck.Outcome != task.PatchCheckPartial {
		t.Fatal(note, report.PatchCheck)
	}
	if !strings.Contains(strings.Join(report.PatchCheck.Files, "\n"), "Смысловая сверка не выполнена") {
		t.Fatal(report.PatchCheck.Files)
	}
}

func TestMeaningWithoutAFunctionNameShowsOnlyThePrelude(t *testing.T) {
	root := t.TempDir()
	rel := "pkg/id.go"
	body := "package p\n\nimport \"fmt\"\n\nfunc Foo() {\n\tcontextLine()\n\ta()\n\tb()\n\tc()\n\td()\n\te()\n\tf()\n\taddedUniqueCall()\n\tmore()\n\tfmt.Println()\n}\n"
	mustWrite(t, filepath.Join(root, rel), body)
	file := task.PatchFile{Filename: rel, Patch: "" +
		"@@\n" +
		" contextLine()\n" +
		"+addedUniqueCall()\n" +
		" more()\n"}
	matches := []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}
	ai := &meaningAI{reply: func(prompt string) (string, error) {
		code := prompt[strings.Index(prompt, "Код:\n")+len("Код:\n"):]
		if strings.Contains(code, "addedUniqueCall") || strings.Contains(code, "func Foo") {
			t.Fatal(prompt)
		}
		return "1: да | addedUniqueCall()", nil
	}}
	yes := true
	report := task.Report{PatchFiles: matches, Reach: &task.ReachReport{Reachable: &yes}}
	note := noteAppliedPatchReviewed(context.Background(), ai, root, []task.PatchFile{file}, &report)
	if note != "" || report.PatchCheck.Outcome != task.PatchCheckPartial {
		t.Fatal(note, report.PatchCheck)
	}
	if !strings.Contains(strings.Join(report.PatchCheck.Files, "\n"), "не нашла") {
		t.Fatal(report.PatchCheck.Files)
	}
}

func driftedHunk(name, added string) task.PatchFile {
	return task.PatchFile{Filename: name, Patch: "" +
		"@@ func Foo\n" +
		" contextLine()\n" +
		"+" + added + "\n" +
		" more()\n"}
}

func driftedBody(added string) string {
	return "package p\n\nfunc Foo() {\n\tcontextLine()\n\ta()\n\tb()\n\tc()\n\td()\n\te()\n\tf()\n\t" + added + "\n\tmore()\n}\n"
}

type meaningAI struct {
	prompts []string
	reply   func(prompt string) (string, error)
}

func (m *meaningAI) Explain(_ context.Context, prompt string) (string, error) {
	m.prompts = append(m.prompts, prompt)
	return m.reply(prompt)
}
