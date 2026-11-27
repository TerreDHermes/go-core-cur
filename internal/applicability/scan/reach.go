package scan

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"cve-patch-viewer/internal/applicability/task"
)

const maxReachFuncs = 8

var funcDecl = regexp.MustCompile(`^func\s+(?:\(([^)]*)\)\s*)?([A-Za-z_][A-Za-z0-9_]*)`)

type namedFunc struct {
	Recv string
	Name string
}

func analyzeReach(ctx context.Context, repoPath string, files []task.PatchFile, matches []task.PatchFileMatch) *task.ReachReport {
	report := &task.ReachReport{Tool: "deadcode", Functions: []task.ReachFunc{}}
	run, stdlib := stdlibFrom(ctx)
	var fns []task.ReachFunc
	seenFn := map[string]bool{}
	var pending []funcAsk
	addFn := func(rel string, fn namedFunc) {
		if len(fns) >= maxReachFuncs {
			return
		}
		key := rel + "\x00" + fn.Recv + "." + fn.Name
		if seenFn[key] {
			return
		}
		// A function the patch deletes is not in this tree. Asking deadcode
		// about it reports the symbol as live, because it is absent from
		// the unreachable list. Only declarations that are still in the file
		// say whether the remaining code is reachable.
		if functionText(repoPath, rel, fn) == "" {
			return
		}
		seenFn[key] = true
		fns = append(fns, reachItem(repoPath, rel, fn, stdlib, run.Goroot))
	}
	for _, match := range matches {
		if !match.Found || !strings.HasSuffix(match.Filename, ".go") || strings.HasSuffix(match.Filename, "_test.go") {
			continue
		}
		diff := patchText(files, match.Filename)
		for _, fn := range functionsInPatch(diff) {
			addFn(match.Path, fn)
		}
		body, err := os.ReadFile(absMatch(repoPath, match.Path))
		if err != nil {
			continue
		}
		text := string(body)
		extra, missing := enclosingPatchFuncs(text, diff)
		for _, fn := range extra {
			addFn(match.Path, fn)
		}
		if missing && !fileHasPatchFunc(fns, match.Path) {
			pending = append(pending, funcAsk{rel: match.Path, body: text, diff: diff})
		}
	}
	if len(fns) == 0 {
		fallback := functionsFromChangedTypes(ctx, repoPath, files, matches, stdlib, run.Goroot)
		switch {
		case fallback.Cancelled:
			report.Detail = ctx.Err().Error()
			return report
		case len(fallback.Funcs) > 0:
			for _, loc := range fallback.Funcs {
				addFn(loc.File, loc.Func)
			}
		case fallback.Unread || fallback.Unresolved || (len(fallback.Unused) > 0 && fallback.Unnamed):
			report.Detail = typeUnknownDetail(fallback)
			return report
		case len(fallback.Unused) > 0:
			v := false
			report.Reachable = &v
			report.Detail = unusedTypeDetail(fallback.Unused)
			return report
		case fallback.HadGo:
			for _, ask := range pending {
				fn, ok := askEnclosingFunc(ctx, reachExplain(ctx), ask)
				if !ok {
					continue
				}
				addFn(ask.rel, fn)
			}
			if len(fns) == 0 {
				report.Detail = "в патче меняется код, но ни функцию, ни тип из него выделить не удалось"
				return report
			}
		default:
			report.Detail = "из патча не удалось выделить функцию"
			return report
		}
	}
	groups := map[string][]int{}
	var order []string
	for i := range fns {
		if fns[i].Symbol == "" {
			fns[i].Status = "failed"
			fns[i].Output = "не удалось собрать путь импорта"
			continue
		}
		var dir string
		var ok bool
		if stdlib {
			dir, ok = run.ModuleDir, run.ModuleDir != ""
		} else {
			dir, ok = moduleDirForFile(repoPath, fns[i].File)
		}
		if !ok {
			fns[i].Status = "failed"
			fns[i].Output = "не найден go.mod для файла"
			continue
		}
		if _, seen := groups[dir]; !seen {
			order = append(order, dir)
		}
		groups[dir] = append(groups[dir], i)
	}
	var skippedNotes []string
	for mi, dir := range order {
		detail := modulePath(filepath.Join(dir, "go.mod"))
		if detail == "" {
			detail = dir
		}
		idxs := groups[dir]
		if ctx.Err() != nil {
			for _, i := range idxs {
				fns[i].Status = "failed"
				fns[i].Output = ctx.Err().Error()
			}
			continue
		}
		if stdlib {
			noteAt(ctx, "проверка импорта stdlib", detail, mi+1, len(order))
			deps, err := listModuleDeps(ctx, dir, hasVendorDir(dir))
			if err != nil {
				for _, i := range idxs {
					fns[i].Status = "failed"
					fns[i].Output = err.Error()
				}
				continue
			}
			pending := make([]int, 0, len(idxs))
			for _, i := range idxs {
				pkg := stdlibImportPath(run.Goroot, fns[i].File)
				if _, imported := deps[pkg]; pkg == "" || !imported {
					fns[i].Status = "missing"
					if pkg == "" {
						fns[i].Output = "не удалось собрать путь импорта"
					} else {
						fns[i].Output = "пакет " + pkg + " не импортируется программой"
					}
					continue
				}
				pending = append(pending, i)
			}
			if len(pending) == 0 {
				continue
			}
			idxs = pending
		}
		noteAt(ctx, "проверка достижимости", detail, mi+1, len(order))
		res := runModuleDeadcode(ctx, dir, hasVendorDir(dir))
		if note := skippedMainsNote(res.Skipped); note != "" {
			skippedNotes = append(skippedNotes, note)
		}
		for _, i := range idxs {
			if fileNamedIn(fns[i].File, res.BrokenFiles) {
				fns[i].Status = "failed"
				fns[i].Output = "файл с уязвимой функцией не компилируется, досягаемость не проверена"
				continue
			}
			fns[i].Status, fns[i].Output = classifyModuleSymbol(res, fns[i].Symbol)
		}
	}
	report.Functions = fns
	report.Reachable, report.Detail = summarizeReach(fns)
	if stdlib && onlyMissingImports(fns) {
		report.Detail = "пакеты стандартной библиотеки из патча программа не импортирует: уязвимый код недостижим, уязвимости в этой сборке нет"
	}
	if extra := strings.Join(skippedNotes, ". "); extra != "" && !strings.Contains(report.Detail, "Из сборки убраны") {
		if report.Detail != "" {
			report.Detail += ". " + extra
		} else {
			report.Detail = extra
		}
	}
	return report
}

func onlyMissingImports(fns []task.ReachFunc) bool {
	if len(fns) == 0 {
		return false
	}
	for _, fn := range fns {
		if fn.Status != "missing" {
			return false
		}
	}
	return true
}

func reachItem(repoPath, file string, fn namedFunc, stdlib bool, goroot string) task.ReachFunc {
	item := reachFunc(repoPath, file, fn)
	if stdlib {
		if pkg := stdlibImportPath(goroot, item.File); pkg != "" {
			item.Symbol = symbolOf(pkg, fn)
		}
	}
	return item
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
		return &v, "deadcode не нашёл функцию среди недостижимого кода: код достижим"
	}
	if anyUnknown {
		return nil, unknownDetail(fns)
	}
	if anyNeg {
		v := false
		return &v, "deadcode нашёл функцию среди недостижимого кода: уязвимый код недостижим, уязвимости в этой сборке нет"
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
		if fn.Status == "failed" && strings.Contains(fn.Output, "не компилируется") {
			return trimOneLine(fn.Output)
		}
	}
	for _, fn := range fns {
		if fn.Status == "failed" && strings.Contains(fn.Output, "ни один main не собрался") {
			return trimOneLine(fn.Output)
		}
	}
	for _, fn := range fns {
		if fn.Status == "failed" && strings.Contains(fn.Output, "не найден в PATH") {
			return "бинарник deadcode не найден в PATH, досягаемость не проверена"
		}
	}
	for _, fn := range fns {
		if fn.Status == "failed" && strings.Contains(fn.Output, "не уложился") {
			return trimOneLine(fn.Output) + ", досягаемость не проверена"
		}
	}
	for _, fn := range fns {
		if fn.Status == "failed" && strings.Contains(fn.Output, "список пакетов не собрался") {
			return trimOneLine(fn.Output) + ", досягаемость не проверена"
		}
	}
	for _, fn := range fns {
		if fn.Status == "failed" && strings.Contains(fn.Output, "команда go недоступна") {
			return "команда go недоступна, досягаемость не проверена"
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
	body, err := os.ReadFile(absMatch(repoPath, rel))
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

type reachExplainKey struct{}

func withReachExplain(ctx context.Context, explain Explainer) context.Context {
	if explain == nil {
		return ctx
	}
	return context.WithValue(ctx, reachExplainKey{}, explain)
}

func reachExplain(ctx context.Context) Explainer {
	explain, _ := ctx.Value(reachExplainKey{}).(Explainer)
	return explain
}

type funcAsk struct {
	rel  string
	body string
	diff string
}

func fileHasPatchFunc(fns []task.ReachFunc, rel string) bool {
	for _, fn := range fns {
		if fn.File == rel {
			return true
		}
	}
	return false
}

// enclosingPatchFuncs names the function that holds a hunk whose header and
// body never say func. The anchor is a removed or context line, not the line
// number in the hunk header. linesMissing is set when such a line is absent
// from the file, which is the only time the model is asked.
func enclosingPatchFuncs(body, diff string) (funcs []namedFunc, linesMissing bool) {
	hunks, ok := parseHunks(diff)
	if !ok {
		return nil, false
	}
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	owners := topLevelFuncs(lines)
	seen := map[string]bool{}
	for _, hunk := range hunks {
		if hunkDeclaresFunc(hunk) {
			continue
		}
		anchors, _ := hunkSearchAnchors(hunk)
		if len(anchors) == 0 {
			continue
		}
		found := anchorLineIndex(lines, anchors)
		if len(found) == 0 {
			linesMissing = true
			continue
		}
		need := 2
		if len(anchors) < 2 {
			need = len(anchors)
		}
		counts := map[string]map[string]bool{}
		var order []namedFunc
		for anchor, idxs := range found {
			for _, idx := range idxs {
				fn, ok := ownerFunc(owners, idx)
				if !ok {
					continue
				}
				key := fn.Recv + "." + fn.Name
				if counts[key] == nil {
					counts[key] = map[string]bool{}
					order = append(order, fn)
				}
				counts[key][anchor] = true
			}
		}
		for _, fn := range order {
			key := fn.Recv + "." + fn.Name
			if len(counts[key]) < need || seen[key] {
				continue
			}
			seen[key] = true
			funcs = append(funcs, fn)
		}
	}
	return funcs, linesMissing
}

func hunkDeclaresFunc(hunk diffHunk) bool {
	if _, ok := parseFuncDecl(hunk.header); ok {
		return true
	}
	for _, line := range hunk.raw {
		if line == "" {
			continue
		}
		switch line[0] {
		case '+', '-', ' ':
			rest := strings.TrimSpace(line[1:])
			if strings.HasPrefix(rest, "func ") || strings.HasPrefix(rest, "func(") {
				return true
			}
		}
	}
	return false
}

// hunkSearchAnchors returns the lines used to find the edit. strong is false
// when the hunk has no distinctive line and only ordinary statements remain.
func hunkSearchAnchors(hunk diffHunk) ([]string, bool) {
	raw := hunkAnchorText(hunk, false)
	if len(raw) == 0 {
		raw = hunkAnchorText(hunk, true)
	}
	var strong, weak []string
	seen := map[string]bool{}
	for _, text := range raw {
		if !usefulAnchor(text) || seen[text] {
			continue
		}
		seen[text] = true
		if strongAnchor(text) {
			strong = append(strong, text)
			continue
		}
		weak = append(weak, text)
	}
	if len(strong) > 0 {
		return strong, true
	}
	return weak, false
}

func hunkAnchorText(hunk diffHunk, added bool) []string {
	var out []string
	if !added {
		for _, line := range hunk.removed {
			out = append(out, strings.TrimSpace(line))
		}
	}
	for _, line := range hunk.lines {
		if line.added != added {
			continue
		}
		out = append(out, strings.TrimSpace(line.text))
	}
	return out
}

func strongAnchor(text string) bool {
	if !usefulAnchor(text) {
		return false
	}
	switch strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(text), "{")) {
	case "return", "return false", "return true", "return nil", "break", "continue", "else", "default":
		return false
	}
	text = strings.TrimSpace(text)
	return len(text) >= 16 || strings.Contains(text, "(")
}

func strongAnchors(diff string) []string {
	hunks, ok := parseHunks(diff)
	if !ok {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, hunk := range hunks {
		anchors, strong := hunkSearchAnchors(hunk)
		if !strong {
			continue
		}
		for _, anchor := range anchors {
			if seen[anchor] {
				continue
			}
			seen[anchor] = true
			out = append(out, anchor)
		}
	}
	return out
}

func anchorLineIndex(lines, anchors []string) map[string][]int {
	want := map[string]bool{}
	for _, anchor := range anchors {
		want[anchor] = true
	}
	found := map[string][]int{}
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if want[trim] {
			found[trim] = append(found[trim], i)
		}
	}
	return found
}

type lineFunc struct {
	fn    namedFunc
	start int
	end   int
}

func topLevelFuncs(lines []string) []lineFunc {
	var out []lineFunc
	for i, line := range lines {
		if !col0Func(line) {
			continue
		}
		fn, _ := parseFuncDecl(line)
		end := funcEnd(lines, i)
		if end < i {
			end = len(lines) - 1
		}
		out = append(out, lineFunc{fn: fn, start: i, end: end})
	}
	return out
}

func col0Func(line string) bool {
	if line == "" || line[0] == ' ' || line[0] == '\t' {
		return false
	}
	_, ok := parseFuncDecl(line)
	return ok
}

func ownerFunc(owners []lineFunc, idx int) (namedFunc, bool) {
	var best *lineFunc
	for i := range owners {
		if owners[i].start < idx && idx <= owners[i].end {
			if best == nil || owners[i].start > best.start {
				best = &owners[i]
			}
		}
	}
	if best == nil {
		return namedFunc{}, false
	}
	return best.fn, true
}

const maxFuncAskBytes = 150000

func askEnclosingFunc(ctx context.Context, explain Explainer, ask funcAsk) (namedFunc, bool) {
	if explain == nil || ctx.Err() != nil {
		return namedFunc{}, false
	}
	body := ask.body
	if len(body) > maxFuncAskBytes {
		body = body[:maxFuncAskBytes]
	}
	text, err := explain.Explain(ctx, funcAskPrompt(ask.rel, ask.diff, body))
	if err != nil {
		return namedFunc{}, false
	}
	return funcQuotedInFile(ask.body, text)
}

func funcAskPrompt(filename, diff, body string) string {
	return "В diff нет имени функции, и строки diff в файле не совпали дословно.\n" +
		"Файл: " + filename + "\n\nDiff:\n" + diff + "\n\nКод файла:\n" + body + "\n\n" +
		"Напиши одну строку: точное объявление func из кода файла, внутри которого сделана правка.\n" +
		"Строка должна быть скопирована из файла без изменений. Если такой строки нет, напиши НЕТ.\n" +
		"Никакого другого текста."
}

func funcQuotedInFile(body, answer string) (namedFunc, bool) {
	answer = strings.TrimSpace(answer)
	if answer == "" || strings.EqualFold(answer, "НЕТ") {
		return namedFunc{}, false
	}
	var found namedFunc
	n := 0
	for _, line := range strings.Split(body, "\n") {
		if !col0Func(line) {
			continue
		}
		trim := strings.TrimSpace(line)
		if !strings.Contains(answer, trim) {
			continue
		}
		fn, ok := parseFuncDecl(trim)
		if !ok {
			continue
		}
		found = fn
		n++
	}
	if n != 1 {
		return namedFunc{}, false
	}
	return found, true
}

// locateGoByAnchors finds Go files that contain the hunk lines when the patch
// path itself was not matched. Non-Go files are ignored. A file counts when
// it holds two distinctive lines, or the only distinctive line.
func locateGoByAnchors(repoPath string, files []task.PatchFile) []task.PatchFileMatch {
	var matches []task.PatchFileMatch
	for _, file := range files {
		if !strings.HasSuffix(file.Filename, ".go") || strings.HasSuffix(file.Filename, "_test.go") {
			continue
		}
		anchors := strongAnchors(file.Patch)
		if len(anchors) == 0 {
			continue
		}
		need := 2
		if len(anchors) == 1 {
			need = 1
		}
		type hit struct {
			path string
			n    int
		}
		var hits []hit
		_ = filepath.WalkDir(repoPath, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if d.Name() == ".git" {
					return fs.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
				return nil
			}
			info, infoErr := d.Info()
			if infoErr != nil || info.Size() > maxGrepFileBytes {
				return nil
			}
			raw, readErr := os.ReadFile(p)
			if readErr != nil || bytes.IndexByte(raw, 0) >= 0 {
				return nil
			}
			n := len(anchorLineIndex(strings.Split(string(raw), "\n"), anchors))
			if n < need {
				return nil
			}
			rel, relErr := filepath.Rel(repoPath, p)
			if relErr != nil {
				return nil
			}
			hits = append(hits, hit{path: "./" + filepath.ToSlash(rel), n: n})
			return nil
		})
		sort.Slice(hits, func(i, j int) bool {
			if hits[i].n != hits[j].n {
				return hits[i].n > hits[j].n
			}
			return hits[i].path < hits[j].path
		})
		for _, item := range hits {
			if len(matches) >= maxReachFuncs {
				break
			}
			matches = append(matches, task.PatchFileMatch{
				Filename: file.Filename,
				Found:    true,
				Path:     item.path,
			})
		}
	}
	return matches
}
