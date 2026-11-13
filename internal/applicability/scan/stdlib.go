package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"cve-patch-viewer/internal/applicability/task"
)

// stdlibPackage is the Trivy name for the Go standard library.
// Its sources are not in vendor: they come with the toolchain named by go.mod.
const stdlibPackage = "stdlib"

const toolchainFetchLimit = 2 * time.Minute

type stdlibKey struct{}

// stdlibRun is one module checked against one Go toolchain.
type stdlibRun struct {
	ModuleDir string
	Toolchain string
	Goroot    string
}

func isStdlib(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), stdlibPackage)
}

func withStdlib(ctx context.Context, run stdlibRun) context.Context {
	return context.WithValue(ctx, stdlibKey{}, run)
}

func stdlibFrom(ctx context.Context) (stdlibRun, bool) {
	run, ok := ctx.Value(stdlibKey{}).(stdlibRun)
	return run, ok && run.ModuleDir != "" && run.Goroot != ""
}

func toolchainFrom(ctx context.Context) string {
	run, ok := ctx.Value(stdlibKey{}).(stdlibRun)
	if !ok {
		return ""
	}
	return run.Toolchain
}

// goRelease is the toolchain named by one go.mod.
// Pinned is false when the file has no patch number, as in "go 1.22".
type goRelease struct {
	Toolchain string
	Pinned    bool
	Line      string
}

var (
	pinnedToolchain = regexp.MustCompile(`^go1\.\d+\.\d+$`)
	pinnedGoVersion = regexp.MustCompile(`^1\.\d+\.\d+$`)
)

func goReleaseOf(content string) goRelease {
	var goLine, toolLine string
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "go":
			if goLine == "" {
				goLine = fields[1]
			}
		case "toolchain":
			if toolLine == "" {
				toolLine = fields[1]
			}
		}
	}
	if toolLine != "" && toolLine != "local" && toolLine != "default" {
		if pinnedToolchain.MatchString(toolLine) {
			return goRelease{Toolchain: toolLine, Pinned: true, Line: "toolchain " + toolLine}
		}
		return goRelease{Line: "toolchain " + toolLine}
	}
	if pinnedGoVersion.MatchString(goLine) {
		return goRelease{Toolchain: "go" + goLine, Pinned: true, Line: "go " + goLine}
	}
	if goLine != "" {
		return goRelease{Line: "go " + goLine}
	}
	return goRelease{}
}

func directiveLines(content string) []string {
	var lines []string
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && (fields[0] == "go" || fields[0] == "toolchain") {
			lines = append(lines, line)
		}
	}
	return lines
}

// lookupToolchain resolves GOTOOLCHAIN=name to its GOROOT. Tests replace it.
var lookupToolchain = runLookupToolchain

func runLookupToolchain(ctx context.Context, moduleDir, name string) (string, error) {
	if !pinnedToolchain.MatchString(name) {
		return "", fmt.Errorf("некорректное имя тулчейна %s", name)
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(parent, toolchainFetchLimit)
	defer cancel()
	env := setEnv(append([]string{}, os.Environ()...), "GOTOOLCHAIN", name)
	stdout, stderr, err := runGrouped(ctx, moduleDir, env, "go", "env", "GOROOT")
	if err != nil {
		if parent.Err() != nil {
			return "", parent.Err()
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", fmt.Errorf("тулчейн %s не скачался за %s", name, minutesRu(toolchainFetchLimit))
		}
		msg := strings.TrimSpace(stderr)
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("%s", trimRunOutput(msg))
	}
	goroot := strings.TrimSpace(stdout)
	info, statErr := os.Stat(filepath.Join(goroot, "src"))
	if goroot == "" || statErr != nil || !info.IsDir() {
		return "", fmt.Errorf("тулчейн %s не содержит исходников", name)
	}
	return goroot, nil
}

func locateStdlibFiles(goroot string, files []task.PatchFile) []task.PatchFileMatch {
	matches := make([]task.PatchFileMatch, 0, len(files))
	for _, file := range files {
		match := task.PatchFileMatch{Filename: file.Filename}
		if abs, ok := stdlibAbs(goroot, file.Filename); ok {
			match.Found = true
			match.Path = abs
		}
		matches = append(matches, match)
	}
	return matches
}

func stdlibAbs(goroot, name string) (string, bool) {
	rel := filepath.ToSlash(strings.TrimSpace(name))
	rel = strings.TrimPrefix(rel, "/")
	rel = strings.TrimPrefix(rel, "src/")
	if rel == "" || strings.Contains(rel, "..") {
		return "", false
	}
	srcRoot := filepath.Join(goroot, "src")
	abs := filepath.Join(srcRoot, filepath.FromSlash(rel))
	if !within(srcRoot, abs) {
		return "", false
	}
	info, err := os.Stat(abs)
	if err != nil || info.IsDir() {
		return "", false
	}
	return abs, true
}

func stdlibImportPath(goroot, absFile string) string {
	srcRoot := filepath.Join(goroot, "src")
	rel, err := filepath.Rel(srcRoot, filepath.Dir(absFile))
	if err != nil {
		return ""
	}
	rel = filepath.ToSlash(rel)
	if rel == "" || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return ""
	}
	return rel
}

func symbolOf(pkg string, fn namedFunc) string {
	if pkg == "" || fn.Name == "" {
		return ""
	}
	if fn.Recv != "" {
		return pkg + "." + fn.Recv + "." + fn.Name
	}
	return pkg + "." + fn.Name
}

// listModuleDeps is the import set of ./... . Tests replace it.
// A standard package missing from this set is not in the built program.
var listModuleDeps = runListDeps

func runListDeps(ctx context.Context, moduleDir string, useVendor bool) (map[string]struct{}, error) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		return nil, fmt.Errorf("команда go недоступна")
	}
	if err := acquireDeadcode(ctx); err != nil {
		return nil, err
	}
	defer releaseDeadcode()
	started := time.Now()
	listCtx, cancel := context.WithTimeout(ctx, toolchainFetchLimit)
	defer cancel()
	stdout, stderr, err := runGrouped(listCtx, moduleDir, deadcodeEnv(ctx, useVendor), goBin, "list", "-deps", "-f", "{{.ImportPath}}", "./...")
	if err != nil {
		if errors.Is(listCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil && time.Since(started) >= toolchainFetchLimit-2*time.Second {
			return nil, fmt.Errorf("список пакетов не собрался за %s", minutesRu(toolchainFetchLimit))
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		msg := strings.TrimSpace(stderr)
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%s", trimRunOutput(msg))
	}
	deps := map[string]struct{}{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			deps[line] = struct{}{}
		}
	}
	return deps, nil
}

func scanStdlib(ctx context.Context, in Input, patches PatchSource, explain Explainer, notes *task.DevNotes) ([]task.ModuleResult, error) {
	paths, err := findGoMods(ctx, in.RepoPath)
	if err != nil {
		return nil, err
	}
	if p := ProgressFrom(ctx); p != nil {
		p.SetGoMods(len(paths))
	}
	if patches == nil {
		return nil, fmt.Errorf("cve patch source is not configured")
	}
	note(ctx, "загрузка патча")
	patch, err := patches.Fetch(ctx, in.CVEID)
	if err != nil {
		return nil, fmt.Errorf("cve patch for: %w", err)
	}
	if len(paths) == 0 {
		result := task.ModuleResult{
			GoModPath: "-",
			Verdict:   "go.mod нет, версию стандартной библиотеки взять неоткуда. Досягаемость не проверялась.",
			ReportMD:  task.Report{Stage: task.StageStdlibUnpinned, Patch: patch},
		}
		return finish(ctx, in, []task.ModuleResult{result}, explain, notes)
	}
	var found []task.ModuleResult
	for i, rel := range paths {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		noteAt(ctx, "чтение версии Go", "./"+rel, i+1, len(paths))
		result, err := analyzeStdlibModule(ctx, in, patch, rel, i+1, len(paths))
		if err != nil {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		found = append(found, result)
	}
	return finish(ctx, in, found, explain, notes)
}

func analyzeStdlibModule(ctx context.Context, in Input, patch task.CVEPatch, rel string, index, total int) (task.ModuleResult, error) {
	goModPath := "./" + rel
	absMod := filepath.Join(in.RepoPath, filepath.FromSlash(rel))
	moduleDir := filepath.Dir(absMod)
	body, err := os.ReadFile(absMod)
	if err != nil {
		return task.ModuleResult{}, fmt.Errorf("read %s: %w", rel, err)
	}
	release := goReleaseOf(string(body))
	report := task.Report{
		GoModPath:     goModPath,
		HasVendor:     hasVendorDir(moduleDir),
		MatchingLines: directiveLines(string(body)),
		Version:       release.Toolchain,
		Patch:         patch,
	}
	if !release.Pinned {
		report.Stage = task.StageStdlibUnpinned
		text := "В " + goModPath + " уровень патча стандартной библиотеки не закреплён"
		if release.Line != "" {
			text += " (" + release.Line + ")"
		}
		text += ". Проверить нечего."
		return task.ModuleResult{GoModPath: goModPath, Verdict: text, ReportMD: report}, nil
	}
	noteAt(ctx, "загрузка тулчейна", release.Toolchain, index, total)
	goroot, err := lookupToolchain(ctx, moduleDir, release.Toolchain)
	if err != nil {
		if ctx.Err() != nil {
			return task.ModuleResult{}, ctx.Err()
		}
		report.Stage = task.StageStdlibNoSource
		result := task.ModuleResult{
			GoModPath: goModPath,
			Verdict: fmt.Sprintf(
				"Стандартная библиотека Go %s по версии уязвима, но её исходники не скачались: %s. Досягаемость не проверялась.",
				release.Toolchain, err.Error(),
			),
			ReportMD: report,
		}
		return result, nil
	}
	if len(patch.Files) == 0 {
		report.Stage = task.StageNoPatch
		return task.ModuleResult{
			GoModPath: goModPath,
			Verdict:   fmt.Sprintf("Стандартная библиотека Go %s скачана, но в патче нет файлов. Досягаемость не проверялась.", release.Toolchain),
			ReportMD:  report,
		}, nil
	}
	matches := locateStdlibFiles(goroot, patch.Files)
	report.Stage = task.StagePatchFiles
	report.PatchFiles = matches
	report.FoundPatchFiles = foundPaths(matches)
	ctx = withStdlib(ctx, stdlibRun{ModuleDir: moduleDir, Toolchain: release.Toolchain, Goroot: goroot})
	verdict := verdictStdlibFiles(release.Toolchain, report.FoundPatchFiles)
	verdict += attachReach(ctx, in.RepoPath, patch, &report)
	result := task.ModuleResult{GoModPath: goModPath, Verdict: verdict, ReportMD: report}
	result.Verdict += noteAppliedPatch(in.RepoPath, patch.Files, &result.ReportMD)
	return result, nil
}

func verdictStdlibFiles(toolchain string, found []string) string {
	text := fmt.Sprintf("Стандартная библиотека Go %s взята из тулчейна.", toolchain)
	if len(found) == 0 {
		return text + " Ни один файл патча в её исходниках не найден."
	}
	return text + " В исходниках найдены файлы патча: " + strings.Join(found, ", ") + "."
}
