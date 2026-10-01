package scan

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"cveanalysis/internal/task"
)

const maxReachFuncs = 8

var funcDecl = regexp.MustCompile(`^func\s+(?:\(([^)]*)\)\s*)?([A-Za-z_][A-Za-z0-9_]*)`)

type namedFunc struct {
	Recv string
	Name string
}

func analyzeReach(ctx context.Context, repoPath string, files []task.PatchFile, matches []task.PatchFileMatch) *task.ReachReport {
	report := &task.ReachReport{Tool: "deadcode", Functions: []task.ReachFunc{}}
	var fns []task.ReachFunc
	for _, match := range matches {
		if !match.Found || !strings.HasSuffix(match.Filename, ".go") || strings.HasSuffix(match.Filename, "_test.go") {
			continue
		}
		diff := patchText(files, match.Filename)
		for _, fn := range functionsInPatch(diff) {
			if len(fns) >= maxReachFuncs {
				break
			}
			fns = append(fns, reachFunc(repoPath, match.Path, fn))
		}
	}
	if len(fns) == 0 {
		report.Detail = "из патча не удалось выделить функцию"
		return report
	}
	for i := range fns {
		if ctx.Err() != nil {
			fns[i].Status = "failed"
			fns[i].Output = ctx.Err().Error()
			continue
		}
		if fns[i].Symbol == "" {
			fns[i].Status = "failed"
			fns[i].Output = "не удалось собрать путь импорта"
			continue
		}
		dir, ok := moduleDirForFile(repoPath, fns[i].File)
		if !ok {
			fns[i].Status = "failed"
			fns[i].Output = "не найден go.mod для файла"
			continue
		}
		status, output, err := whyLiveFunc(ctx, dir, hasVendorDir(dir), fns[i].Symbol)
		fns[i].Status = status
		fns[i].Output = strings.TrimSpace(output)
		if err != nil && fns[i].Output == "" {
			fns[i].Output = err.Error()
		}
	}
	report.Functions = fns
	report.Reachable, report.Detail = summarizeReach(fns)
	return report
}

func reachFunc(repoPath, rel string, fn namedFunc) task.ReachFunc {
	symbol := ""
	if pkg := importPathOf(repoPath, rel); pkg != "" {
		symbol = pkg + "." + fn.Name
		if fn.Recv != "" {
			symbol = pkg + "." + fn.Recv + "." + fn.Name
		}
	}
	return task.ReachFunc{
		Symbol: symbol,
		File:   rel,
		Text:   functionText(repoPath, rel, fn),
	}
}

func summarizeReach(fns []task.ReachFunc) (*bool, string) {
	anyLive := false
	anyNeg := false
	anyUnknown := false
	for _, fn := range fns {
		switch fn.Status {
		case "live":
			anyLive = true
		case "dead", "missing":
			anyNeg = true
		default:
			anyUnknown = true
		}
	}
	if anyLive {
		v := true
		return &v, "deadcode нашёл путь от main до уязвимой функции: код достижим"
	}
	if anyUnknown {
		return nil, unknownDetail(fns)
	}
	if anyNeg {
		v := false
		return &v, "deadcode не нашёл пути от main до уязвимой функции: уязвимый код недостижим, уязвимости в этой сборке нет"
	}
	return nil, "досягаемость от main не проверена"
}

func unknownDetail(fns []task.ReachFunc) string {
	for _, fn := range fns {
		if fn.Status == "no-main" {
			return "в модуле нет package main, досягаемость не проверена"
		}
	}
	for _, fn := range fns {
		if fn.Status == "failed" && strings.Contains(fn.Output, "не найден в PATH") {
			return "бинарник deadcode не найден в PATH, досягаемость не проверена"
		}
	}
	for _, fn := range fns {
		if fn.Status == "failed" && fn.Output != "" {
			return "deadcode не смог разобрать сборку, досягаемость не проверена: " + trimOneLine(fn.Output)
		}
	}
	return "досягаемость от main не проверена"
}

func trimOneLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func reachFacts(r *task.ReachReport) string {
	if r == nil || r.Detail == "" {
		return ""
	}
	return " " + r.Detail + "."
}

func patchText(files []task.PatchFile, name string) string {
	for _, file := range files {
		if file.Filename == name {
			return file.Patch
		}
	}
	return ""
}

func functionsInPatch(diff string) []namedFunc {
	var out []namedFunc
	seen := map[string]bool{}
	add := func(line string) {
		fn, ok := parseFuncDecl(line)
		if !ok {
			return
		}
		key := fn.Recv + "." + fn.Name
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, fn)
	}
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "@@") {
			if i := strings.LastIndex(line, "@@"); i >= 0 {
				add(line[i+2:])
			}
			continue
		}
		if line == "" {
			continue
		}
		switch line[0] {
		case '+', '-', ' ':
			rest := strings.TrimSpace(line[1:])
			if strings.HasPrefix(rest, "func ") || strings.HasPrefix(rest, "func(") {
				add(rest)
			}
		}
	}
	return out
}

func parseFuncDecl(line string) (namedFunc, bool) {
	line = strings.TrimSpace(line)
	m := funcDecl.FindStringSubmatch(line)
	if m == nil {
		return namedFunc{}, false
	}
	return namedFunc{Recv: receiverType(m[1]), Name: m[2]}, true
}

func receiverType(params string) string {
	params = strings.TrimSpace(params)
	if params == "" {
		return ""
	}
	fields := strings.Fields(params)
	typ := fields[len(fields)-1]
	typ = strings.TrimLeft(typ, "*")
	if i := strings.LastIndex(typ, "."); i >= 0 {
		typ = typ[i+1:]
	}
	if i := strings.IndexByte(typ, '['); i >= 0 {
		typ = typ[:i]
	}
	return typ
}

func importPathOf(repoPath, rel string) string {
	slash := filepath.ToSlash(strings.TrimPrefix(rel, "./"))
	const marker = "vendor/"
	if i := strings.Index(slash, marker); i >= 0 {
		dir := path.Dir(slash[i+len(marker):])
		if dir == "." {
			return ""
		}
		return dir
	}
	moduleDir, ok := moduleDirForFile(repoPath, rel)
	if !ok {
		return ""
	}
	mod := modulePath(filepath.Join(moduleDir, "go.mod"))
	if mod == "" {
		return ""
	}
	fileDir := filepath.Dir(filepath.Join(repoPath, filepath.FromSlash(slash)))
	relDir, err := filepath.Rel(moduleDir, fileDir)
	if err != nil {
		return ""
	}
	relDir = filepath.ToSlash(relDir)
	if relDir == "." || relDir == "" {
		return mod
	}
	return path.Join(mod, relDir)
}

func modulePath(goMod string) string {
	body, err := os.ReadFile(goMod)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "module" {
			return fields[1]
		}
	}
	return ""
}

func moduleDirForFile(repoPath, rel string) (string, bool) {
	slash := strings.TrimPrefix(filepath.ToSlash(rel), "./")
	parts := strings.Split(slash, "/")
	for i, part := range parts {
		if part != "vendor" {
			continue
		}
		if i == 0 {
			return repoPath, true
		}
		return filepath.Join(repoPath, filepath.FromSlash(strings.Join(parts[:i], "/"))), true
	}
	dir := filepath.Dir(filepath.Join(repoPath, filepath.FromSlash(slash)))
	root := filepath.Clean(repoPath)
	for {
		if st, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !st.IsDir() {
			return dir, true
		}
		if dir == root {
			return "", false
		}
		parent := filepath.Dir(dir)
		if parent == dir || !strings.HasPrefix(parent, root) && parent != root {
			return "", false
		}
		dir = parent
	}
}

func hasVendorDir(moduleDir string) bool {
	st, err := os.Stat(filepath.Join(moduleDir, "vendor"))
	return err == nil && st.IsDir()
}

func functionText(repoPath, rel string, fn namedFunc) string {
	body, err := os.ReadFile(filepath.Join(repoPath, filepath.FromSlash(strings.TrimPrefix(rel, "./"))))
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	idx := -1
	for i, line := range lines {
		parsed, ok := parseFuncDecl(line)
		if ok && parsed.Name == fn.Name && parsed.Recv == fn.Recv {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ""
	}
	from, to := excerptSpan(lines, idx, true)
	from, to = shrinkSpan(lines, from, to, idx)
	return formatExcerpt(lines, from, to)
}
