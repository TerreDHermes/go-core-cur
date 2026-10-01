package scan

import (
	"context"
	"fmt"
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
}

func (f fakePatch) Fetch(context.Context, string) (task.CVEPatch, error) {
	files := f.files
	if files == nil {
		files = []task.PatchFile{{Filename: "a.go", Patch: "diff"}}
	}
	return task.CVEPatch{CVE: f.cve, Files: files}, nil
}

func TestScanStopsWhenRepositoryIsNotGo(t *testing.T) {
	got, err := Scan(context.Background(), Input{RepoPath: t.TempDir(), PackageName: "pkg"}, fakePatch{}, staticAI{})
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

func (c *captureAI) Explain(_ context.Context, prompt string) (string, error) {
	c.prompts = append(c.prompts, prompt)
	return "model-verdict", nil
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
	if len(ai.prompts) != 1 {
		t.Fatal(len(ai.prompts))
	}
	prompt := ai.prompts[0]
	for _, part := range []string{
		`Потенциальная уязвимость CVE-2026-24051 (GHSA-abcd) применима к компоненту "alertmanager"`,
		`используется зависимость "go.opentelemetry.io/otel/sdk" версии "v1.43.0"`,
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

func TestScanFailsWhenAIFails(t *testing.T) {
	_, err := Scan(context.Background(), Input{RepoPath: t.TempDir(), PackageName: "pkg"}, fakePatch{}, failAI{})
	if err == nil || !strings.Contains(err.Error(), "ai verdict") {
		t.Fatal(err)
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
