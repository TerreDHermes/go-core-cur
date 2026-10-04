package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cveanalysis/internal/applicability/task"
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
	}, fakePatch{cve: "CVE-2024-1"}, staticAI{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d results: %+v", len(got), got)
	}
	if got[0].GoModPath != "./go.mod" || got[1].GoModPath != "./tools/go.mod" {
		t.Fatalf("%+v", got)
	}
	if got[0].ReportMD.Stage != task.StagePatchFiles || !strings.Contains(got[0].ReportMD.PreVerdict, "Ни один файл патча в vendor не найден") {
		t.Fatal(got[0].ReportMD.PreVerdict)
	}
	if got[0].Verdict != "model-verdict" || got[0].ReportMD.Version != "v1.2.3" || got[1].ReportMD.Version != "v1.2.3" {
		t.Fatalf("verdict %q versions %q %q", got[0].Verdict, got[0].ReportMD.Version, got[1].ReportMD.Version)
	}
	if got[0].Applicability != task.NotApplicable || got[1].Applicability != task.Uncertain {
		t.Fatalf("%s %s", got[0].Applicability, got[1].Applicability)
	}
	if len(got[0].ReportMD.PatchFiles) != 1 || got[0].ReportMD.PatchFiles[0].Found || got[0].ReportMD.PatchFiles[0].Filename != "a.go" {
		t.Fatalf("%+v", got[0].ReportMD.PatchFiles)
	}
	if got[1].ReportMD.Stage != task.StageNoVendor || !strings.Contains(got[1].ReportMD.PreVerdict, "без vendor анализ невозможен") {
		t.Fatal(got[1].ReportMD.PreVerdict)
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
	fixed []string
}

func (f fakePatch) Fetch(context.Context, string) (task.CVEPatch, error) {
	files := f.files
	if files == nil {
		files = []task.PatchFile{{Filename: "a.go", Patch: "diff"}}
	}
	return task.CVEPatch{CVE: f.cve, Files: files, FixedVersions: f.fixed}, nil
}

func TestScanNotGoGrepsPatchAndReadsNotes(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "dapp", "README.md"), "parseToken нельзя звать на сыром вводе.\n")
	mustWrite(t, filepath.Join(root, "src", "auth.py"), "def parseToken(raw):\n    return raw\n")
	ai := &captureAI{}
	got, err := Scan(context.Background(), Input{
		RepoPath:     root,
		ComponentURL: "https://example.com/widgets",
		CVEID:        "CVE-2024-9",
		PackageName:  "widgets",
	}, fakePatch{cve: "CVE-2024-9", files: []task.PatchFile{{
		Filename: "src/auth.py",
		Patch:    "@@ -1,2 +1,3 @@\n def parseToken(raw):\n-    return raw\n+    raise ValueError(\"token rejected\")\n",
	}}}, ai)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ReportMD.Stage != task.StageNotGo {
		t.Fatalf("%+v", got)
	}
	grep := got[0].ReportMD.Grep
	if grep == nil || grep.Source != "patch" || !containsAll(grep.Patterns, "parseToken", "token rejected") {
		t.Fatalf("%+v", grep)
	}
	if !hitPath(grep.Hits, "./src/auth.py") || !hitPath(grep.Hits, "./dapp/README.md") {
		t.Fatal(grep.Hits)
	}
	if !excerptHas(grep.Excerpts, "./src/auth.py", "parseToken") {
		t.Fatal(grep.Excerpts)
	}
	if got[0].ReportMD.DevNotes == nil || !strings.Contains(got[0].ReportMD.DevNotes.Text, "сыром вводе") {
		t.Fatalf("%+v", got[0].ReportMD.DevNotes)
	}
	pre := got[0].ReportMD.PreVerdict
	for _, part := range []string{"Заметки разработчиков", "не на Go", "из патча", "parseToken", "Кусков файлов сохранено: 2"} {
		if !strings.Contains(pre, part) {
			t.Fatal(pre)
		}
	}
	if len(ai.prompts) != 2 {
		t.Fatal(len(ai.prompts))
	}
	if !strings.Contains(ai.prompts[0], `применима к компоненту "widgets"`) || !strings.Contains(ai.prompts[0], "не на Go") || !strings.Contains(ai.prompts[0], "сыром вводе") {
		t.Fatal(ai.prompts[0])
	}
	if !strings.Contains(ai.prompts[1], "подробный журнал") || !strings.Contains(ai.prompts[1], "model-verdict") {
		t.Fatal(ai.prompts[1])
	}
	if got[0].ReportMD.Narrative != "narrative-text" || got[0].Verdict != "model-verdict" {
		t.Fatalf("verdict %q narrative %q", got[0].Verdict, got[0].ReportMD.Narrative)
	}
}

func TestScanNotGoGrepsDescriptionWithoutNotes(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "lib.py"), "def HostID():\n    return 1\n")
	ai := &captureAI{}
	got, err := Scan(context.Background(), Input{
		RepoPath:     root,
		ComponentURL: "https://example.com/widgets",
		CVEID:        "CVE-2026-24051",
		PackageName:  "widgets",
	}, describedPatch{}, ai)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ReportMD.Stage != task.StageNotGo || got[0].ReportMD.DevNotes != nil {
		t.Fatalf("%+v", got[0].ReportMD.DevNotes)
	}
	if got[0].ReportMD.Grep == nil || got[0].ReportMD.Grep.Source != "description" {
		t.Fatalf("%+v", got[0].ReportMD.Grep)
	}
	if strings.Join(got[0].ReportMD.Grep.Patterns, ",") != "HostID,readMachineID" {
		t.Fatal(got[0].ReportMD.Grep.Patterns)
	}
	if len(got[0].ReportMD.Grep.Hits) != 1 || got[0].ReportMD.Grep.Hits[0].Path != "./lib.py" {
		t.Fatal(got[0].ReportMD.Grep.Hits)
	}
	if strings.Contains(got[0].ReportMD.PreVerdict, "dapp") {
		t.Fatal(got[0].ReportMD.PreVerdict)
	}
	if !strings.Contains(got[0].ReportMD.PreVerdict, "Файлов в патче нет") || !strings.Contains(got[0].ReportMD.PreVerdict, "из описания") {
		t.Fatal(got[0].ReportMD.PreVerdict)
	}
	if len(ai.prompts) != 3 || !strings.Contains(ai.prompts[1], "не на Go") || !strings.Contains(ai.prompts[1], "неопределенна") || !strings.Contains(ai.prompts[2], "файла не было") {
		t.Fatalf("prompts %d", len(ai.prompts))
	}
}

func hitPath(hits []task.GrepHit, path string) bool {
	for _, hit := range hits {
		if hit.Path == path {
			return true
		}
	}
	return false
}

func excerptHas(excerpts []task.GrepExcerpt, path, text string) bool {
	for _, excerpt := range excerpts {
		if excerpt.Path == path && strings.Contains(excerpt.Text, text) {
			return true
		}
	}
	return false
}

func containsAll(items []string, want ...string) bool {
	got := map[string]bool{}
	for _, item := range items {
		got[item] = true
	}
	for _, item := range want {
		if !got[item] {
			return false
		}
	}
	return true
}

func TestScanFindsPatchedFileInVendor(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/root\n\nrequire github.com/foo/bar v1.2.3\n")
	mustWrite(t, filepath.Join(root, "vendor", "github.com", "foo", "bar", "a.go"), "package bar\n")

	got, err := Scan(context.Background(), Input{
		RepoPath:    root,
		CVEID:       "CVE-2024-1",
		PackageName: "github.com/foo/bar",
	}, fakePatch{cve: "CVE-2024-1"}, staticAI{})
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
	if !strings.Contains(got[0].ReportMD.PreVerdict, "./vendor/github.com/foo/bar/a.go") {
		t.Fatal(got[0].ReportMD.PreVerdict)
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
	}}, staticAI{})
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
	if got[0].ReportMD.Version != "" {
		t.Fatal(got[0].ReportMD.Version)
	}
	if !strings.Contains(got[0].ReportMD.PreVerdict, "go.mod не искался") || !strings.Contains(got[0].ReportMD.PreVerdict, "./sdk/resource/host_id.go") {
		t.Fatal(got[0].ReportMD.PreVerdict)
	}
	if strings.Contains(got[0].ReportMD.PreVerdict, "vendor") {
		t.Fatal(got[0].ReportMD.PreVerdict)
	}
	if !strings.Contains(got[0].ReportMD.Markdown(), "`sdk/resource/missing.go`: false") {
		t.Fatal(got[0].ReportMD.Markdown())
	}
}

func TestScanRootWithoutGoMod(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.txt"), "not go\n")
	got, err := Scan(context.Background(), Input{RepoPath: root, PackageName: "root"}, fakePatch{files: []task.PatchFile{}}, staticAI{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ReportMD.Stage != task.StageNoPatch || !strings.Contains(got[0].ReportMD.PreVerdict, "патч не найден") {
		t.Fatalf("%+v", got[0])
	}
}

func TestScanRootAllMissing(t *testing.T) {
	root := t.TempDir()
	got, err := Scan(context.Background(), Input{RepoPath: root, PackageName: "root"}, fakePatch{files: []task.PatchFile{{Filename: "a.go"}}}, staticAI{})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ReportMD.PatchFiles[0].Found || len(got[0].ReportMD.FoundPatchFiles) != 0 {
		t.Fatal(got[0].ReportMD)
	}
	if !strings.Contains(got[0].ReportMD.PreVerdict, "Ни один файл патча в корне не найден") {
		t.Fatal(got[0].ReportMD.PreVerdict)
	}
}

func scanOne(t *testing.T, root, pkg string, files []task.PatchFile) task.ModuleResult {
	t.Helper()
	got, err := Scan(context.Background(), Input{
		RepoPath:    root,
		CVEID:       "CVE-2026-24051",
		PackageName: pkg,
	}, fakePatch{cve: "CVE-2026-24051", files: files}, staticAI{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	return got[0]
}

type staticAI struct{}

func (staticAI) Explain(context.Context, string) (string, error) {
	return "model-verdict", nil
}

type captureAI struct {
	prompts []string
}

type failAI struct{}

func (failAI) Explain(context.Context, string) (string, error) {
	return "", fmt.Errorf("down")
}

func TestModuleVersionPrefersRequire(t *testing.T) {
	body := `
module example.com/app

require (
    go.opentelemetry.io/otel/sdk v1.43.0 // indirect
)

exclude go.opentelemetry.io/otel/sdk v1.42.0
replace go.opentelemetry.io/otel/sdk => go.opentelemetry.io/otel/sdk v1.43.1
`
	if got := moduleVersion(body, "go.opentelemetry.io/otel/sdk"); got != "v1.43.0" {
		t.Fatal(got)
	}
	if got := moduleVersion("exclude github.com/foo/bar v1.2.2\n", "github.com/foo/bar"); got != "v1.2.2" {
		t.Fatal(got)
	}
}

func TestScanPromptTemplates(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/alertmanager\n\nrequire go.opentelemetry.io/otel/sdk v1.43.0\n")
	mustWrite(t, filepath.Join(root, "vendor", "go.opentelemetry.io", "otel", "sdk", "resource", "host_id.go"), "package resource\n")

	ai := &captureAI{}
	_, err := Scan(context.Background(), Input{
		RepoPath:     root,
		ComponentURL: "https://github.com/prometheus/alertmanager.git",
		CVEID:        "CVE-2026-24051",
		PackageName:  "go.opentelemetry.io/otel/sdk",
	}, aliasPatch{}, ai)
	if err != nil {
		t.Fatal(err)
	}
	if len(ai.prompts) != 2 || !strings.Contains(ai.prompts[1], "подробный журнал") {
		t.Fatal(len(ai.prompts))
	}
	prompt := ai.prompts[0]
	for _, part := range []string{
		`Потенциальная уязвимость CVE-2026-24051 (GHSA-abcd) пока не оценена для компонента "alertmanager"`,
		`зависимость "go.opentelemetry.io/otel/sdk" версии "v1.43.0"`,
		`проверка досягаемости не дала ответа`,
		`"version": "v1.43.0"`,
		"host_id.go",
	} {
		if !strings.Contains(prompt, part) {
			t.Fatalf("missing %s\n%s", part, prompt)
		}
	}

	missing := t.TempDir()
	mustWrite(t, filepath.Join(missing, "go.mod"), "module example.com/alertmanager\n\nrequire go.opentelemetry.io/otel/sdk v1.43.0\n")
	if err := os.MkdirAll(filepath.Join(missing, "vendor"), 0o755); err != nil {
		t.Fatal(err)
	}
	ai = &captureAI{}
	_, err = Scan(context.Background(), Input{
		RepoPath:     missing,
		ComponentURL: "https://github.com/prometheus/alertmanager",
		CVEID:        "CVE-2026-24051",
		PackageName:  "go.opentelemetry.io/otel/sdk",
	}, fakePatch{cve: "CVE-2026-24051"}, ai)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ai.prompts[0], `неприменима к компоненту "alertmanager", хоть и используется зависимость "go.opentelemetry.io/otel/sdk" версии "v1.43.0"`) {
		t.Fatal(ai.prompts[0])
	}
}

func TestParseKeywordsKeepsFiveGrepPhrases(t *testing.T) {
	got := parseKeywords("1. HostID\n- readMachineID\n`otel resource`\nxx\nHostID\nbonus one\nbonus two\n")
	want := []string{"HostID", "readMachineID", "otel resource", "bonus one", "bonus two"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatal(got)
	}
}

func TestGrepIsWordMatchAndBounded(t *testing.T) {
	root := t.TempDir()
	var b strings.Builder
	for i := 0; i < 6; i++ {
		fmt.Fprintf(&b, "UniqueToken %d\n", i)
	}
	b.WriteString("OtherToken\n")
	b.WriteString("HostIDExtra\n")
	mustWrite(t, filepath.Join(root, "lib.go"), "func HostID() {}\n"+b.String())
	mustWrite(t, filepath.Join(root, ".git", "config"), "HostID\n")
	mustWrite(t, filepath.Join(root, "bin.dat"), "HostID\x00more\n")

	hits, _, truncated, _, err := grepRepo(context.Background(), root, []string{"HostID", "UniqueToken", "OtherToken"})
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Fatal("expected truncation")
	}
	var host, unique, other int
	for _, hit := range hits {
		if strings.Contains(hit.Path, ".git") || strings.Contains(hit.Text, "HostIDExtra") || hit.Path == "./bin.dat" {
			t.Fatal(hit)
		}
		switch hit.Pattern {
		case "HostID":
			host++
			if hit.Path != "./lib.go" || hit.Line != 1 {
				t.Fatal(hit)
			}
		case "UniqueToken":
			unique++
		case "OtherToken":
			other++
		}
	}
	if host != 1 || unique != maxHitsPerPattern || other != 1 {
		t.Fatalf("host %d unique %d other %d hits %+v", host, unique, other, hits)
	}
}

func TestExcerptKeepsEnclosingFunction(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "host.go"), `package resource

func Other() {
	println("other")
}

func HostID() string {
	id := readMachineID()
	return id
}

func Tail() {
	println("tail")
}
`)
	_, excerpts, _, excerptsTruncated, err := grepRepo(context.Background(), root, []string{"readMachineID"})
	if err != nil {
		t.Fatal(err)
	}
	if excerptsTruncated || len(excerpts) != 1 {
		t.Fatalf("%+v", excerpts)
	}
	text := excerpts[0].Text
	if !strings.Contains(text, "func HostID") || !strings.Contains(text, "return id") {
		t.Fatal(text)
	}
	if strings.Contains(text, "func Other") || strings.Contains(text, "func Tail") {
		t.Fatal(text)
	}
}

func TestScanGrepsWhenPatchIsMissing(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/alertmanager\n\nrequire go.opentelemetry.io/otel/sdk v1.43.0\n")
	if err := os.MkdirAll(filepath.Join(root, "vendor"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "sdk", "resource", "host.go"), "package resource\n\nfunc HostID() {}\n")
	mustWrite(t, filepath.Join(root, ".git", "config"), "HostID\n")

	ai := &captureAI{}
	got, err := Scan(context.Background(), Input{
		RepoPath:     root,
		ComponentURL: "https://github.com/prometheus/alertmanager",
		CVEID:        "CVE-2026-24051",
		PackageName:  "go.opentelemetry.io/otel/sdk",
	}, describedPatch{}, ai)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ReportMD.Stage != task.StageNoPatch || got[0].ReportMD.Grep == nil {
		t.Fatalf("%+v", got)
	}
	if strings.Join(got[0].ReportMD.Grep.Patterns, ",") != "HostID,readMachineID" {
		t.Fatal(got[0].ReportMD.Grep.Patterns)
	}
	if len(got[0].ReportMD.Grep.Hits) != 1 || got[0].ReportMD.Grep.Hits[0].Path != "./sdk/resource/host.go" {
		t.Fatal(got[0].ReportMD.Grep.Hits)
	}
	if !strings.Contains(got[0].ReportMD.PreVerdict, "HostID, readMachineID") || !strings.Contains(got[0].ReportMD.PreVerdict, "Совпадений сохранено: 1") {
		t.Fatal(got[0].ReportMD.PreVerdict)
	}
	if len(ai.prompts) != 3 || !strings.Contains(ai.prompts[0], "grep -rwn") {
		t.Fatalf("prompts %d", len(ai.prompts))
	}
	if !strings.Contains(ai.prompts[1], "применима") || !strings.Contains(ai.prompts[1], "неприменима") || !strings.Contains(ai.prompts[1], "неопределенна") || !strings.Contains(ai.prompts[1], "func HostID") {
		t.Fatal(ai.prompts[1])
	}
	if len(got[0].ReportMD.Grep.Excerpts) != 1 || !strings.Contains(got[0].ReportMD.Grep.Excerpts[0].Text, "func HostID") {
		t.Fatal(got[0].ReportMD.Grep.Excerpts)
	}
	if !strings.Contains(got[0].ReportMD.Markdown(), "Grep truncated") && got[0].ReportMD.Grep.Truncated {
		t.Fatal(got[0].ReportMD.Markdown())
	}
	if !strings.Contains(got[0].ReportMD.Markdown(), "`HostID`") {
		t.Fatal(got[0].ReportMD.Markdown())
	}
}

func TestScanGrepsWithoutVendorWhenPatchIsMissing(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\nrequire github.com/foo/bar v1.2.3\n")
	mustWrite(t, filepath.Join(root, "main.go"), "package main\n\nfunc HostID() {}\n")
	got, err := Scan(context.Background(), Input{
		RepoPath:    root,
		CVEID:       "CVE-1",
		PackageName: "github.com/foo/bar",
	}, describedPatch{}, &captureAI{})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ReportMD.Stage != task.StageNoVendor || got[0].ReportMD.Grep == nil || len(got[0].ReportMD.Grep.Hits) != 1 {
		t.Fatalf("%+v", got[0].ReportMD)
	}
}

type describedPatch struct{}

func (describedPatch) Fetch(context.Context, string) (task.CVEPatch, error) {
	return task.CVEPatch{
		CVE:           "CVE-2026-24051",
		Description:   "HostID is derived from a machine identifier.",
		DescriptionRU: "Идентификатор хоста строится из readMachineID.",
	}, nil
}

func (c *captureAI) Explain(_ context.Context, prompt string) (string, error) {
	c.prompts = append(c.prompts, prompt)
	if strings.Contains(prompt, "grep -rwn") {
		return "HostID\nreadMachineID\n", nil
	}
	if strings.Contains(prompt, "подробный журнал") {
		return "narrative-text", nil
	}
	return "model-verdict", nil
}

func TestScanFailsWhenAIFails(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n")
	_, err := Scan(context.Background(), Input{RepoPath: root, PackageName: "pkg"}, fakePatch{}, failAI{})
	if err == nil || !strings.Contains(err.Error(), "ai verdict") {
		t.Fatal(err)
	}
}

func TestDecideApplicabilityFollowsTheAnalysis(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name    string
		report  task.Report
		verdict string
		want    string
	}{
		{"live", task.Report{Reach: &task.ReachReport{Reachable: &yes}}, "неприменима", task.Applicable},
		{"dead", task.Report{Reach: &task.ReachReport{Reachable: &no}}, "применима", task.NotApplicable},
		{"grep no", task.Report{Grep: &task.GrepReport{}}, "Уязвимость неприменима к компоненту", task.NotApplicable},
		{"grep empty but model says yes", task.Report{Grep: &task.GrepReport{}}, "Потенциальная уязвимость применима", task.NotApplicable},
		{"grep unclear", task.Report{Grep: &task.GrepReport{Hits: []task.GrepHit{{Path: "a.py"}}}}, "model-verdict", task.Uncertain},
		{"grep ambiguous", task.Report{Grep: &task.GrepReport{Hits: []task.GrepHit{{Path: "a.py"}}}}, "Уязвимость неопределенна: совпадения не про код.", task.Uncertain},
		{"no vendor", task.Report{Stage: task.StageNoVendor}, "пока не оценена", task.Uncertain},
		{"files missing", task.Report{Stage: task.StagePatchFiles, PatchFiles: []task.PatchFileMatch{{Found: false}}}, "", task.NotApplicable},
		{"files found", task.Report{Stage: task.StagePatchFiles, PatchFiles: []task.PatchFileMatch{{Found: true}}}, "применима", task.Uncertain},
		{"version fixed", task.Report{VersionStatus: versionFixed}, "применима", task.NotApplicable},
	}
	for _, tc := range cases {
		if got := decideApplicability(tc.report, tc.verdict); got != tc.want {
			t.Fatalf("%s: got %s", tc.name, got)
		}
	}
}

func TestVersionGateStaysOnTheSameReleaseLine(t *testing.T) {
	fixed := []string{"v1.1.9", "1.3.0"}
	status, threshold := versionGate("v1.1.10", fixed)
	if status != versionFixed || threshold != "v1.1.9" {
		t.Fatalf("%s %s", status, threshold)
	}
	status, threshold = versionGate("v1.1.8", fixed)
	if status != versionVulnerable || threshold != "v1.1.9" {
		t.Fatalf("%s %s", status, threshold)
	}
	status, threshold = versionGate("v1.2.4", fixed)
	if status != versionUnknown || threshold != "" {
		t.Fatalf("%s %s", status, threshold)
	}
	status, threshold = versionGate("v1.3.0", fixed)
	if status != versionFixed || threshold != "v1.3.0" {
		t.Fatalf("%s %s", status, threshold)
	}
	status, _ = versionGate("v1.2.3-rc.1", []string{"v1.2.3"})
	if status != versionVulnerable {
		t.Fatal(status)
	}
	status, _ = versionGate("v1.2.1, v1.2.4", []string{"v1.2.3"})
	if status != versionVulnerable {
		t.Fatal(status)
	}
	status, _ = versionGate("", fixed)
	if status != versionUnknown {
		t.Fatal(status)
	}
}

func TestScanStopsWhenVersionIsAlreadyFixed(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\nrequire github.com/foo/bar v1.2.4\n")
	mustWrite(t, filepath.Join(root, "vendor", "github.com", "foo", "bar", "a.go"), "package bar\n\nfunc HostID() {}\n")
	got, err := Scan(context.Background(), Input{
		RepoPath:     root,
		ComponentURL: "https://example.com/app",
		CVEID:        "CVE-1",
		PackageName:  "github.com/foo/bar",
	}, fakePatch{cve: "CVE-1", fixed: []string{"v1.2.3"}, files: []task.PatchFile{{
		Filename: "a.go",
		Patch:    "@@ -1 +1 @@\n func HostID() {}\n",
	}}}, staticAI{})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ReportMD.Stage != task.StageVersionFixed || got[0].ReportMD.Reach != nil {
		t.Fatalf("%+v", got[0].ReportMD)
	}
	if got[0].Applicability != task.NotApplicable || got[0].ReportMD.FixedVersion != "v1.2.3" {
		t.Fatalf("%s %s", got[0].Applicability, got[0].ReportMD.FixedVersion)
	}
	if !strings.Contains(got[0].ReportMD.PreVerdict, "v1.2.4") || !strings.Contains(got[0].ReportMD.PreVerdict, "v1.2.3") {
		t.Fatal(got[0].ReportMD.PreVerdict)
	}
}

func TestVersionOnAnotherLineDoesNotStopTheScan(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\nrequire github.com/foo/bar v1.2.4\n")
	if err := os.MkdirAll(filepath.Join(root, "vendor"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := Scan(context.Background(), Input{
		RepoPath:    root,
		CVEID:       "CVE-1",
		PackageName: "github.com/foo/bar",
	}, fakePatch{cve: "CVE-1", fixed: []string{"v1.1.9", "v1.3.0"}}, staticAI{})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ReportMD.Stage != task.StagePatchFiles || got[0].ReportMD.VersionStatus != versionUnknown {
		t.Fatalf("stage %s status %s", got[0].ReportMD.Stage, got[0].ReportMD.VersionStatus)
	}
	if got[0].Applicability != task.NotApplicable {
		t.Fatal(got[0].Applicability)
	}
}

func TestVulnerableVersionContinuesAndEmptyGrepIsNotApplicable(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\nrequire github.com/foo/bar v1.2.1\n")
	if err := os.MkdirAll(filepath.Join(root, "vendor"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := Scan(context.Background(), Input{
		RepoPath:     root,
		ComponentURL: "https://example.com/app",
		CVEID:        "CVE-1",
		PackageName:  "github.com/foo/bar",
	}, fakePatch{cve: "CVE-1", fixed: []string{"v1.2.3"}, files: []task.PatchFile{}}, &captureAI{})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ReportMD.Stage != task.StageNoPatch || got[0].ReportMD.VersionStatus != versionVulnerable || got[0].ReportMD.FixedVersion != "v1.2.3" {
		t.Fatalf("%s %s %s", got[0].ReportMD.Stage, got[0].ReportMD.VersionStatus, got[0].ReportMD.FixedVersion)
	}
	if !strings.Contains(got[0].ReportMD.PreVerdict, "ниже исправления") {
		t.Fatal(got[0].ReportMD.PreVerdict)
	}
	if got[0].ReportMD.Grep == nil || len(got[0].ReportMD.Grep.Hits) != 0 || got[0].Applicability != task.NotApplicable {
		t.Fatalf("%+v %s", got[0].ReportMD.Grep, got[0].Applicability)
	}
}

func TestPackageAbsentDoesNotSearchTheTree(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n")
	mustWrite(t, filepath.Join(root, "lib.py"), "def HostID():\n    return 1\n")
	ai := &captureAI{}
	got, err := Scan(context.Background(), Input{
		RepoPath:    root,
		CVEID:       "CVE-1",
		PackageName: "github.com/foo/bar",
	}, describedPatch{}, ai)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ReportMD.Stage != task.StagePackageAbsent || got[0].ReportMD.Grep != nil || got[0].Applicability != task.NotApplicable {
		t.Fatalf("%s %+v %s", got[0].ReportMD.Stage, got[0].ReportMD.Grep, got[0].Applicability)
	}
	if len(ai.prompts) != 2 || strings.Contains(ai.prompts[0], "grep -rwn") {
		t.Fatal(ai.prompts[0])
	}
}

func TestPatchGrepPatternsPreferFunctionsAndLiterals(t *testing.T) {
	got := patchGrepPatterns(task.CVEPatch{Files: []task.PatchFile{{
		Filename: "sdk/resource/host_id.go",
		Patch:    "@@ -1,3 +1,4 @@ func HostID() string {\n \treturn readMachineID()\n+\treturn \"machine id missing\"\n }\n",
	}}})
	if len(got) == 0 || got[0] != "HostID" || !containsAll(got, "machine id missing", "readMachineID", "host_id") {
		t.Fatal(got)
	}
	if len(got) > maxPatchPatterns {
		t.Fatal(len(got))
	}
}

func TestLoadDevNotesSkipsMissingAndTruncates(t *testing.T) {
	missing, err := loadDevNotes(t.TempDir())
	if err != nil || missing != nil {
		t.Fatal(err, missing)
	}
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "dapp", "README.md"), strings.Repeat("я", maxDevNotesRunes+10))
	notes, err := loadDevNotes(root)
	if err != nil || notes == nil || !notes.Truncated || len([]rune(notes.Text)) != maxDevNotesRunes {
		t.Fatalf("%v %+v", err, notes)
	}
}

type aliasPatch struct{}

func (aliasPatch) Fetch(context.Context, string) (task.CVEPatch, error) {
	return task.CVEPatch{
		CVE:     "CVE-2026-24051",
		Aliases: []string{"CVE-2026-24051", "GHSA-abcd"},
		Files:   []task.PatchFile{{Filename: "sdk/resource/host_id.go", Patch: "diff"}},
	}, nil
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
