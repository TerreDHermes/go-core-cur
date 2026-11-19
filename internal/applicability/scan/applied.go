package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cve-patch-viewer/internal/applicability/task"
)

// noteAppliedPatch fills the patch-check dossier and, only for a full match,
// marks the vulnerability not applicable. It does not call the model.
func noteAppliedPatch(repoPath string, files []task.PatchFile, report *task.Report) string {
	return noteAppliedPatchReviewed(context.Background(), nil, repoPath, files, report)
}

// noteAppliedPatchReviewed is noteAppliedPatch, then one model call per code
// file the line check did not fully accept. The call sees the unmatched
// additions and a slice of the file, not the match count. A full result after
// that still marks the vulnerability not applicable. A model error leaves the
// line check as it was.
func noteAppliedPatchReviewed(ctx context.Context, explain Explainer, repoPath string, files []task.PatchFile, report *task.Report) string {
	if report == nil {
		return ""
	}
	check := buildPatchCheck(repoPath, files, report)
	if explain != nil && check != nil && check.Ran && check.Outcome != task.PatchCheckFull {
		check = refinePatchCheck(ctx, explain, repoPath, files, report)
	}
	report.PatchCheck = check
	if check == nil || check.Outcome != task.PatchCheckFull {
		report.PatchApplied = nil
		return ""
	}
	report.PatchApplied = &task.PatchApplied{
		Applied: true,
		Detail:  "все файлы и все фрагменты патча уже есть в коде",
	}
	return " Патч применён целиком: уязвимого кода в этой версии уже нет."
}

func buildPatchCheck(repoPath string, files []task.PatchFile, report *task.Report) *task.PatchCheck {
	if len(files) == 0 {
		return &task.PatchCheck{
			Ran:     false,
			Outcome: task.PatchCheckNotRun,
			Detail:  "Проверка не проводилась: в патче нет файлов, сверять diff с кодом не с чем. На вывод это не повлияло.",
		}
	}
	if onlyMarkdown(files) {
		return &task.PatchCheck{
			Ran:     false,
			Outcome: task.PatchCheckNotRun,
			Detail:  "Проверка не проводилась: патч меняет только markdown-файлы, кода в нём нет. Совпадение этих файлов не доказывает, что уязвимость закрыта. На вывод это не повлияло.",
			Files:   markdownFileLines(files),
		}
	}
	if !hasCheckedFile(files) {
		return &task.PatchCheck{
			Ran:     false,
			Outcome: task.PatchCheckNotRun,
			Detail:  "Проверка не проводилась: патч меняет только тестовые файлы, markdown или txt. Эти файлы в сверке не учитываются и не доказывают, что уязвимость закрыта. На вывод это не повлияло.",
			Files:   ignoredPatchLines(files),
		}
	}
	if len(report.PatchFiles) == 0 {
		return &task.PatchCheck{
			Ran:     false,
			Outcome: task.PatchCheckNotRun,
			Detail:  "Проверка не проводилась: пути файлов патча с этим деревом не сопоставлялись. Вывод «патч уже применён» из этого шага не следует.",
		}
	}
	if !patchFileFound(*report) {
		return &task.PatchCheck{
			Ran:     false,
			Outcome: task.PatchCheckNotRun,
			Detail:  "Проверка не проводилась: файлы патча в этом дереве не найдены. На вывод «патч уже применён» это не повлияло.",
		}
	}
	if report.Reach == nil || report.Reach.Reachable == nil {
		detail := "Проверка не проводилась: досягаемость уязвимой функции не установлена. Пока это так, патч с кодом не сверяется, и вывод не становится «неприменима» из-за уже применённого патча."
		if report.Reach != nil && strings.TrimSpace(report.Reach.Detail) != "" {
			detail = "Проверка не проводилась: досягаемость не установлена (" + strings.TrimSpace(report.Reach.Detail) + "). Патч с кодом не сверялся, вывод из-за этого не становится «неприменима»."
		}
		return &task.PatchCheck{Ran: false, Outcome: task.PatchCheckNotRun, Detail: detail}
	}
	if !*report.Reach.Reachable {
		return &task.PatchCheck{
			Ran:     false,
			Outcome: task.PatchCheckNotRun,
			Detail:  "Проверка не проводилась: уязвимая функция недостижима. Неприменимость здесь из-за недостижимости, а не из-за того, что патч уже лежит в коде.",
		}
	}

	return summarizePatchItems(collectPatchItems(repoPath, files, report))
}

type patchItem struct {
	name   string
	status string
	line   string
}

func collectPatchItems(repoPath string, files []task.PatchFile, report *task.Report) []patchItem {
	items := make([]patchItem, 0, len(files))
	for _, file := range files {
		items = append(items, classifyPatchFile(repoPath, file, report.PatchFiles))
	}
	return items
}

func classifyPatchFile(repoPath string, file task.PatchFile, matches []task.PatchFileMatch) patchItem {
	if isMarkdown(file.Filename) {
		return patchItem{name: file.Filename, status: "markdown", line: "файл " + file.Filename + ": markdown, в сверке не учитывается"}
	}
	if isTextFile(file.Filename) {
		return patchItem{name: file.Filename, status: "text", line: "файл " + file.Filename + ": текст, в сверке не учитывается"}
	}
	if isTestGo(file.Filename) {
		return patchItem{name: file.Filename, status: "test", line: "файл " + file.Filename + ": тест, в сверке не учитывается"}
	}
	status, line := assessPatchFile(repoPath, file, matches)
	return patchItem{name: file.Filename, status: status, line: line}
}

func summarizePatchItems(items []patchItem) *task.PatchCheck {
	var lines []string
	var notApplied []string
	allFull := true
	anyFull := false
	anyPartial := false
	ignoredMD := false
	ignoredTest := false
	ignoredAbsent := false
	ignoredNoFunc := false
	meaningHit := false
	for _, item := range items {
		lines = append(lines, item.line)
		if strings.Contains(item.line, "построчное сравнение не зачло") {
			meaningHit = true
		}
		switch item.status {
		case "full":
			anyFull = true
		case "markdown":
			ignoredMD = true
		case "test":
			ignoredTest = true
		case "absent":
			ignoredAbsent = true
		case "nofunc":
			ignoredNoFunc = true
		case "text":
			// A text file is listed and does not decide whether the patch is present.
		case "partial", "missing":
			allFull = false
			anyPartial = true
			notApplied = append(notApplied, item.name)
		default:
			allFull = false
			notApplied = append(notApplied, item.name)
		}
	}
	switch {
	case allFull:
		detail := "Проверка проводилась. Патч применён целиком: все файлы и все фрагменты diff уже есть в коде."
		if ignoredMD || ignoredTest || ignoredAbsent || ignoredNoFunc {
			detail = "Проверка проводилась. Патч применён целиком: все файлы кода и все фрагменты diff уже есть в коде."
		}
		if ignoredMD {
			detail += " Файлы markdown в сверке не учитывались."
		}
		if ignoredTest {
			detail += " Тестовые файлы в сверке не учитывались."
		}
		if ignoredAbsent {
			detail += " Файлы, которых нет в дереве и которые патч только правит, в сверке не учитывались."
		}
		if ignoredNoFunc {
			detail += " Фрагменты функций, которых нет в коде, в сверке не учитывались."
		}
		if meaningHit {
			detail += " Часть фрагментов зачтена смысловой сверкой."
		}
		detail += " Вывод — неприменима."
		return &task.PatchCheck{
			Ran:     true,
			Outcome: task.PatchCheckFull,
			Detail:  detail,
			Files:   lines,
		}
	case anyPartial:
		check := &task.PatchCheck{
			Ran:     true,
			Outcome: task.PatchCheckPartial,
			Detail:  "Проверка проводилась. Патч применён не целиком. Вывод остаётся «применима»: для неприменимости нужно совпадение на 100 процентов.",
			Files:   lines,
		}
		if anyFull {
			check.NotApplied = notApplied
		}
		return check
	default:
		return &task.PatchCheck{
			Ran:     true,
			Outcome: task.PatchCheckInconclusive,
			Detail:  "Проверка проводилась, но diff не удалось сверить полностью. Доказать, что патч уже применён, нельзя. Вывод остаётся «применима».",
			Files:   lines,
		}
	}
}

func assessPatchFile(repoPath string, file task.PatchFile, matches []task.PatchFileMatch) (string, string) {
	got := inspectPatchFile(repoPath, file, matches)
	return got.status, got.line
}

type patchInspect struct {
	status    string
	line      string
	body      []string
	hunks     []diffHunk
	unmatched []int
	counted   int
	matched   int
	ignored   []string
}

func inspectPatchFile(repoPath string, file task.PatchFile, matches []task.PatchFileMatch) patchInspect {
	match, ok := matchByName(matches, file.Filename)
	if diffDeletesFile(file.Patch) {
		if !ok || !match.Found {
			return patchInspect{status: "full", line: "файл " + file.Filename + " патч удаляет, и в дереве его нет"}
		}
		return patchInspect{status: "partial", line: "файл " + file.Filename + " патч удаляет, но он всё ещё в дереве"}
	}
	if !ok || !match.Found {
		if diffCreatesFile(file.Patch) {
			return patchInspect{status: "missing", line: "файл " + file.Filename + " патч создаёт, но в дереве его нет"}
		}
		return patchInspect{status: "absent", line: "файл " + file.Filename + " в дереве нет, патч его только правит, в сверке не учитывается"}
	}
	if strings.TrimSpace(file.Patch) == "" {
		return patchInspect{status: "unparsed", line: "файл " + file.Filename + ": diff пустой, сверить нельзя"}
	}
	body, err := os.ReadFile(absMatch(repoPath, match.Path))
	if err != nil {
		return patchInspect{status: "unparsed", line: "файл " + file.Filename + " не прочитан"}
	}
	hunks, parsed := parseHunks(file.Patch)
	if !parsed || len(hunks) == 0 {
		return patchInspect{status: "unparsed", line: "файл " + file.Filename + ": diff не разобран по фрагментам"}
	}
	lines := splitLines(string(body))
	got := patchInspect{body: lines, hunks: hunks}
	for i, hunk := range hunks {
		filtered, name, skip := hunkWithoutMissingFunc(lines, hunk)
		if name != "" {
			got.ignored = append(got.ignored, name)
		}
		if skip {
			continue
		}
		got.hunks[i] = filtered
		got.counted++
		if hunkApplied(lines, filtered) {
			got.matched++
			continue
		}
		got.unmatched = append(got.unmatched, i)
	}
	if got.counted == 0 {
		got.status = "nofunc"
		got.line = "файл " + file.Filename + ": функции, которых нет в коде, патч только правит, в сверке не учитывается: " + strings.Join(got.ignored, ", ")
		return got
	}
	got.status, got.line = patchedFileLine(file.Filename, got.matched, got.counted, got.ignored)
	return got
}

func patchedFileLine(name string, matched, counted int, ignored []string) (string, string) {
	note := ""
	if len(ignored) > 0 {
		note = ". Не учитывались правки функций, которых нет в коде: " + strings.Join(ignored, ", ")
	}
	if matched == counted {
		return "full", "файл " + name + ": все фрагменты патча уже в коде" + note
	}
	return "partial", fmt.Sprintf("файл %s: совпали %d из %d фрагментов", name, matched, counted) + note
}

// withPartialPatchNote appends the fixed sentence when some code files
// already contain the patch and some do not. The model does not write it.
func withPartialPatchNote(verdict string, report task.Report) string {
	if report.PatchCheck == nil || len(report.PatchCheck.NotApplied) == 0 {
		return verdict
	}
	note := "Патч частично применен, но в этих файлах патч не применен - " + strings.Join(report.PatchCheck.NotApplied, ", ") + "."
	verdict = strings.TrimSpace(verdict)
	if verdict == "" {
		return note
	}
	if strings.HasSuffix(verdict, note) {
		return verdict
	}
	last := verdict[len(verdict)-1]
	if last == '.' || last == '!' || last == '?' || strings.HasSuffix(verdict, "…") {
		return verdict + " " + note
	}
	return verdict + ". " + note
}

func patchFullyApplied(repoPath string, files []task.PatchFile, matches []task.PatchFileMatch) bool {
	sawCode := false
	for _, file := range files {
		if ignoredPatchName(file.Filename) {
			continue
		}
		status, _ := assessPatchFile(repoPath, file, matches)
		if status == "absent" || status == "nofunc" {
			continue
		}
		sawCode = true
		if status != "full" {
			return false
		}
	}
	return sawCode
}

func isMarkdown(name string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(name)), ".md")
}

func isTextFile(name string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(name)), ".txt")
}

func isTestGo(name string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(name)), "_test.go")
}

// ignoredPatchName is a documentation, notes, or Go test file.
// Those paths are removed before the tree is searched.
func ignoredPatchName(name string) bool {
	return isMarkdown(name) || isTextFile(name) || isTestGo(name)
}

func codePatchFiles(files []task.PatchFile) []task.PatchFile {
	kept := make([]task.PatchFile, 0, len(files))
	for _, file := range files {
		if ignoredPatchName(file.Filename) {
			continue
		}
		kept = append(kept, file)
	}
	return kept
}

func hasCheckedFile(files []task.PatchFile) bool {
	for _, file := range files {
		if !ignoredPatchName(file.Filename) {
			return true
		}
	}
	return false
}

func onlyMarkdown(files []task.PatchFile) bool {
	if len(files) == 0 {
		return false
	}
	for _, file := range files {
		if !isMarkdown(file.Filename) {
			return false
		}
	}
	return true
}

func markdownFileLines(files []task.PatchFile) []string {
	lines := make([]string, 0, len(files))
	for _, file := range files {
		lines = append(lines, "файл "+file.Filename+": markdown, в сверке не учитывается")
	}
	return lines
}

func ignoredPatchLines(files []task.PatchFile) []string {
	lines := make([]string, 0, len(files))
	for _, file := range files {
		if isTestGo(file.Filename) {
			lines = append(lines, "файл "+file.Filename+": тест, в сверке не учитывается")
			continue
		}
		if isTextFile(file.Filename) {
			lines = append(lines, "файл "+file.Filename+": текст, в сверке не учитывается")
			continue
		}
		lines = append(lines, "файл "+file.Filename+": markdown, в сверке не учитывается")
	}
	return lines
}

type hunkLine struct {
	text  string
	added bool
}

type diffHunk struct {
	header  string
	lines   []hunkLine
	removed []string
	raw     []string
}

func parseHunks(diff string) ([]diffHunk, bool) {
	var hunks []diffHunk
	var current *diffHunk
	flush := func() {
		if current == nil {
			return
		}
		hunks = append(hunks, *current)
		current = nil
	}
	for _, line := range strings.Split(diff, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "@@") {
			flush()
			current = &diffHunk{header: hunkHeader(line)}
			continue
		}
		if current == nil {
			if strings.Contains(line, "Binary files") || strings.Contains(line, "GIT binary patch") {
				return nil, false
			}
			continue
		}
		current.raw = append(current.raw, line)
		if strings.HasPrefix(line, `\`) {
			continue
		}
		if line == "" {
			current.lines = append(current.lines, hunkLine{})
			continue
		}
		switch line[0] {
		case '+':
			current.lines = append(current.lines, hunkLine{text: line[1:], added: true})
		case '-':
			current.removed = append(current.removed, line[1:])
		case ' ':
			current.lines = append(current.lines, hunkLine{text: line[1:]})
		default:
			return nil, false
		}
	}
	flush()
	if len(hunks) == 0 {
		return nil, false
	}
	return hunks, true
}

func hunkHeader(line string) string {
	i := strings.LastIndex(line, "@@")
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(line[i+2:])
}

// hunkWithoutMissingFunc drops edits that land in a function the file does not
// have. The @@ header names that function when it is the only declaration.
// When the header function is in the file, a later func line without a plus
// names the function that owns the lines under it. A func line the patch adds
// is a new function and stays in the hunk. skip means nothing is left to count.
func hunkWithoutMissingFunc(file []string, hunk diffHunk) (diffHunk, string, bool) {
	if fn, ok := parseFuncDecl(hunk.header); ok && !funcExists(file, fn) {
		if hunkCreatesFunc(hunk) {
			return hunk, "", false
		}
		return hunk, funcLabel(fn), true
	}

	old := map[string]bool{}
	markOld := func(line string) {
		fn, ok := parseFuncDecl(line)
		if !ok {
			return
		}
		old[funcLabel(fn)] = true
	}
	for _, line := range hunk.removed {
		markOld(line)
	}
	for _, line := range hunk.lines {
		if line.added {
			continue
		}
		markOld(line.text)
	}

	var owner namedFunc
	haveOwner := false
	if fn, ok := parseFuncDecl(hunk.header); ok {
		owner = fn
		haveOwner = true
	}
	introduced := map[string]bool{}
	ownsMissing := func() bool {
		if !haveOwner || introduced[funcLabel(owner)] {
			return false
		}
		return !funcExists(file, owner)
	}

	var kept []hunkLine
	var keptRemoved []string
	var keptRaw []string
	var ignored []string
	seen := map[string]bool{}
	note := func(fn namedFunc) {
		label := funcLabel(fn)
		if label == "" || seen[label] {
			return
		}
		seen[label] = true
		ignored = append(ignored, label)
	}
	origEdit := false
	keptEdit := false
	for _, raw := range hunk.raw {
		if raw == "" || strings.HasPrefix(raw, `\`) {
			if !ownsMissing() {
				keptRaw = append(keptRaw, raw)
				if raw == "" {
					kept = append(kept, hunkLine{})
				}
			}
			continue
		}
		prefix, text := raw[0], raw[1:]
		if prefix != '+' && prefix != '-' && prefix != ' ' {
			continue
		}
		if fn, ok := parseFuncDecl(text); ok {
			owner = fn
			haveOwner = true
			if prefix == '+' && !old[funcLabel(fn)] {
				introduced[funcLabel(fn)] = true
			}
		}
		if prefix == '+' || prefix == '-' {
			origEdit = true
		}
		if ownsMissing() {
			if prefix == '+' || prefix == '-' {
				note(owner)
			}
			continue
		}
		keptRaw = append(keptRaw, raw)
		switch prefix {
		case '+':
			kept = append(kept, hunkLine{text: text, added: true})
			keptEdit = true
		case '-':
			keptRemoved = append(keptRemoved, text)
			keptEdit = true
		default:
			kept = append(kept, hunkLine{text: text})
		}
	}
	names := strings.Join(ignored, ", ")
	if !origEdit {
		return hunk, "", false
	}
	if !keptEdit {
		return hunk, names, true
	}
	next := hunk
	next.lines = kept
	next.removed = keptRemoved
	next.raw = keptRaw
	return next, names, false
}

func funcLabel(fn namedFunc) string {
	if fn.Name == "" {
		return ""
	}
	if fn.Recv != "" {
		return fn.Recv + "." + fn.Name
	}
	return fn.Name
}

func hunkCreatesFunc(hunk diffHunk) bool {
	old := map[string]bool{}
	mark := func(line string) {
		fn, ok := parseFuncDecl(line)
		if !ok {
			return
		}
		old[fn.Recv+"."+fn.Name] = true
	}
	for _, line := range hunk.removed {
		mark(line)
	}
	for _, line := range hunk.lines {
		if line.added {
			continue
		}
		mark(line.text)
	}
	for _, line := range hunk.lines {
		if !line.added {
			continue
		}
		fn, ok := parseFuncDecl(line.text)
		if !ok {
			continue
		}
		if !old[fn.Recv+"."+fn.Name] {
			return true
		}
	}
	return false
}

func funcExists(file []string, fn namedFunc) bool {
	for _, line := range file {
		got, ok := parseFuncDecl(line)
		if !ok {
			continue
		}
		if got.Name == fn.Name && got.Recv == fn.Recv {
			return true
		}
	}
	return false
}

// patchContextGap is how many code lines around an edit are still the same
// place. The neighbor from the hunk may sit up to three code lines away; a
// matching statement further away is a different function.
const patchContextGap = 4

// hunkApplied reports whether the file already contains this hunk.
// The edit is the tokens the new side adds. They must appear in order, and
// the line must match from its start through the last of those tokens. The
// rest of that line may differ: it is context the patch did not change.
// Added lines with other code between them are separate edits: each one may
// sit anywhere, so a resorted import still counts. A single edit keeps its
// nearest unchanged line above and below nearby, so total++ does not match a
// copy in another function. Indentation, blank lines and comments are ignored.
// A removed line cancels a single edit only inside that window. When the hunk
// holds several separate edits, the removed lines must be gone from the file.
// A pure deletion is applied when the removed code is gone from the file.
func hunkApplied(file []string, hunk diffHunk) bool {
	got := codeLines(file)
	runs, removed, ok := editRuns(hunk)
	if !ok {
		if len(removed) > 0 {
			return !containsContiguous(got, removed)
		}
		return true
	}
	if len(runs) == 1 {
		run := runs[0]
		return blockMatches(got, run.block, run.before, run.after, removed)
	}
	if removedLinesRemain(got, removed, runs) {
		return false
	}
	for _, run := range runs {
		if !blockFound(got, run.block) {
			return false
		}
	}
	return true
}

// linePat is one code line of the edit. prefix set means the file line must
// start with those tokens and may continue differently. Otherwise text must
// match the whole line.
type linePat struct {
	text   string
	prefix []string
}

type codePiece struct {
	text  string
	added bool
}

type editRun struct {
	block  []linePat
	before string
	after  string
}

// editRuns splits a hunk where unchanged code sits between additions.
// Consecutive added lines stay one run. The const that follows an import
// block is its own run, so the import may move among its neighbors.
func editRuns(hunk diffHunk) (runs []editRun, removed []string, ok bool) {
	var pieces []codePiece
	for _, line := range hunk.lines {
		text := codeText(line.text)
		if text == "" {
			continue
		}
		pieces = append(pieces, codePiece{text: text, added: line.added})
	}
	removed = codeLines(hunk.removed)
	var addedAt []int
	var added [][]string
	for i, piece := range pieces {
		if !piece.added {
			continue
		}
		addedAt = append(addedAt, i)
		added = append(added, tokenize(piece.text))
	}
	if len(addedAt) == 0 {
		return nil, removed, false
	}
	keep := insertedTokens(removed, added)
	pats := make([]linePat, len(addedAt))
	pos := 0
	for n, toks := range added {
		pats[n] = linePat{text: pieces[addedAt[n]].text}
		lineKeep := keep[pos : pos+len(toks)]
		pos += len(toks)
		if prefix, drifted := requiredPrefix(toks, lineKeep); drifted {
			pats[n].prefix = prefix
		}
	}
	start := 0
	for n := 1; n <= len(addedAt); n++ {
		if n < len(addedAt) && addedAt[n] == addedAt[n-1]+1 {
			continue
		}
		runs = append(runs, runBetween(pieces, addedAt[start], addedAt[n-1], pats[start:n]))
		start = n
	}
	return runs, removed, true
}

func runBetween(pieces []codePiece, first, last int, block []linePat) editRun {
	run := editRun{block: append([]linePat(nil), block...)}
	if first > 0 {
		run.before = pieces[first-1].text
	}
	if last+1 < len(pieces) {
		run.after = pieces[last+1].text
	}
	return run
}

func removedLinesRemain(file, removed []string, runs []editRun) bool {
	skip := map[string]bool{}
	for _, run := range runs {
		for _, line := range run.block {
			if line.text != "" {
				skip[line.text] = true
			}
		}
	}
	for _, line := range removed {
		if skip[line] {
			continue
		}
		if containsContiguous(file, []string{line}) {
			return true
		}
	}
	return false
}

func blockFound(file []string, block []linePat) bool {
	if len(block) == 0 || len(block) > len(file) {
		return false
	}
	for i := 0; i <= len(file)-len(block); i++ {
		if blockAt(file, i, block) {
			return true
		}
	}
	return false
}

// insertedTokens reports, for every token of the added lines, whether it is
// part of the longest common subsequence with the removed lines. A false
// entry is text the patch introduced.
func insertedTokens(removed []string, added [][]string) []bool {
	var old, neu []string
	for _, line := range removed {
		old = append(old, tokenize(line)...)
	}
	for _, line := range added {
		neu = append(neu, line...)
	}
	return lcsKeep(old, neu)
}

// requiredPrefix is the added line through its last new token. drifted is
// false when the line has no new token, so the whole line must match.
func requiredPrefix(tokens []string, keep []bool) (prefix []string, drifted bool) {
	last := -1
	for i, shared := range keep {
		if !shared {
			last = i
		}
	}
	if last < 0 {
		return tokens, false
	}
	return tokens[:last+1], true
}

func blockMatches(file []string, block []linePat, before, after string, removed []string) bool {
	if len(block) == 0 || len(block) > len(file) {
		return false
	}
	for i := 0; i <= len(file)-len(block); i++ {
		if !blockAt(file, i, block) {
			continue
		}
		beforeAt, beforeOK := neighborAt(file, i, -1, before)
		if !beforeOK {
			continue
		}
		afterAt, afterOK := neighborAt(file, i+len(block), +1, after)
		if !afterOK {
			continue
		}
		anchor := hunkAnchor{before: before, after: after, removed: removed, span: len(block)}
		if removedRemains(file, anchor, i, beforeAt, afterAt) {
			continue
		}
		return true
	}
	return false
}

func blockAt(file []string, at int, block []linePat) bool {
	for j, pat := range block {
		if !lineMatches(file[at+j], pat) {
			return false
		}
	}
	return true
}

func lineMatches(line string, pat linePat) bool {
	if pat.prefix == nil {
		return line == pat.text
	}
	got := tokenize(line)
	return len(got) >= len(pat.prefix) && linesEqual(got[:len(pat.prefix)], pat.prefix)
}

type hunkAnchor struct {
	before  string
	after   string
	removed []string
	span    int
}

// neighborAt finds want within patchContextGap code lines of origin.
// dir -1 looks backward from the line before origin. dir +1 looks forward
// from origin itself. An empty want means the hunk has no neighbor there.
func neighborAt(file []string, origin, dir int, want string) (int, bool) {
	if want == "" {
		return -1, true
	}
	for step := 0; step < patchContextGap; step++ {
		idx := origin + step
		if dir < 0 {
			idx = origin - 1 - step
		}
		if idx < 0 || idx >= len(file) {
			return -1, false
		}
		if file[idx] == want {
			return idx, true
		}
	}
	return -1, false
}

// removedRemains reports the hunk's old code still sitting next to this
// match. The same text inside the added lines is the new code, so an
// indent-only change still counts as applied. An old copy outside the
// window does not.
func removedRemains(file []string, anchor hunkAnchor, addedAt, beforeAt, afterAt int) bool {
	if len(anchor.removed) == 0 {
		return false
	}
	lo := addedAt
	hi := addedAt + anchor.span
	if anchor.before != "" {
		lo = beforeAt + 1
	} else {
		lo = addedAt - patchContextGap
		if lo < 0 {
			lo = 0
		}
	}
	if anchor.after != "" {
		hi = afterAt
	} else if end := hi + patchContextGap; end < len(file) {
		hi = end
	} else {
		hi = len(file)
	}
	if lo < 0 {
		lo = 0
	}
	if hi > len(file) {
		hi = len(file)
	}
	if lo > hi {
		return false
	}
	spanLo := addedAt - lo
	spanHi := addedAt + anchor.span - lo
	return containsOutside(file[lo:hi], anchor.removed, spanLo, spanHi)
}

func lcsKeep(old, neu []string) []bool {
	keep := make([]bool, len(neu))
	n, m := len(old), len(neu)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if old[i] == neu[j] {
				dp[i][j] = dp[i+1][j+1] + 1
				continue
			}
			if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
				continue
			}
			dp[i][j] = dp[i][j+1]
		}
	}
	i, j := 0, 0
	for i < n && j < m {
		if old[i] == neu[j] && dp[i][j] == dp[i+1][j+1]+1 {
			keep[j] = true
			i++
			j++
			continue
		}
		if i+1 <= n && (j+1 > m || dp[i+1][j] >= dp[i][j+1]) {
			i++
			continue
		}
		j++
	}
	return keep
}

func tokenize(line string) []string {
	var out []string
	for i := 0; i < len(line); {
		c := line[i]
		if c == ' ' {
			i++
			continue
		}
		if c == '"' || c == '\'' || c == '`' {
			j := i + 1
			for j < len(line) && line[j] != c {
				if line[j] == '\\' && c != '`' && j+1 < len(line) {
					j += 2
					continue
				}
				j++
			}
			if j < len(line) {
				j++
			}
			out = append(out, line[i:j])
			i = j
			continue
		}
		if isTokenIdent(c) {
			j := i + 1
			for j < len(line) && isTokenIdent(line[j]) {
				j++
			}
			out = append(out, line[i:j])
			i = j
			continue
		}
		if i+1 < len(line) {
			switch line[i : i+2] {
			case "||", "&&", "++", "--", "+=", "-=", "==", "!=", "<=", ">=", ":=", "<-":
				out = append(out, line[i:i+2])
				i += 2
				continue
			}
		}
		out = append(out, line[i:i+1])
		i++
	}
	return out
}

func isTokenIdent(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func containsOutside(window, needle []string, spanLo, spanHi int) bool {
	if len(needle) == 0 || len(needle) > len(window) {
		return false
	}
	for i := 0; i <= len(window)-len(needle); i++ {
		if !linesEqual(window[i:i+len(needle)], needle) {
			continue
		}
		if i >= spanLo && i+len(needle) <= spanHi {
			continue
		}
		return true
	}
	return false
}

// codeLines keeps the code of each line. Indentation, repeated spaces,
// blank lines and comments are dropped, so a patched file still matches
// when the indent or a comment differs.
func codeLines(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		text := codeText(line)
		if text == "" {
			continue
		}
		out = append(out, text)
	}
	return out
}

func codeText(line string) string {
	var b strings.Builder
	var quote byte
	escaped := false
	raw := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if raw {
			b.WriteByte(c)
			if c == '`' {
				raw = false
			}
			continue
		}
		if quote != 0 {
			b.WriteByte(c)
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' && quote == '"' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' || c == '`' {
			quote = c
			if c == '`' {
				raw = true
				quote = 0
			}
			b.WriteByte(c)
			continue
		}
		if c == '/' && i+1 < len(line) && line[i+1] == '/' {
			break
		}
		if c == '/' && i+1 < len(line) && line[i+1] == '*' {
			end := strings.Index(line[i+2:], "*/")
			if end < 0 {
				break
			}
			i += 2 + end + 1
			continue
		}
		b.WriteByte(c)
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

func indexContiguous(file, needle []string) int {
	if len(needle) == 0 || len(needle) > len(file) {
		return -1
	}
	for i := 0; i <= len(file)-len(needle); i++ {
		if linesEqual(file[i:i+len(needle)], needle) {
			return i
		}
	}
	return -1
}

func containsContiguous(file, needle []string) bool {
	return indexContiguous(file, needle) >= 0
}

func linesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// diffCreatesFile reports a patch that adds the whole file.
// An edit of a file that already existed has context or removed lines.
func diffCreatesFile(diff string) bool {
	if strings.TrimSpace(diff) == "" {
		return true
	}
	sawOld := false
	for _, line := range strings.Split(diff, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "new file mode") || strings.HasPrefix(line, "--- /dev/null") || strings.HasPrefix(line, "--- a/dev/null") {
			return true
		}
		if line == "" || strings.HasPrefix(line, `\`) || strings.HasPrefix(line, "diff ") || strings.HasPrefix(line, "index ") || strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "old mode") || strings.HasPrefix(line, "new mode") || strings.HasPrefix(line, "deleted file") || strings.HasPrefix(line, "similarity ") || strings.HasPrefix(line, "rename ") {
			continue
		}
		switch line[0] {
		case '+':
		case '-', ' ':
			sawOld = true
		}
	}
	return !sawOld
}

func diffDeletesFile(diff string) bool {
	for _, line := range strings.Split(diff, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "@@") {
			return false
		}
		if strings.HasPrefix(line, "+++ /dev/null") || strings.HasPrefix(line, "+++ b/dev/null") {
			return true
		}
	}
	return false
}

func matchByName(matches []task.PatchFileMatch, name string) (task.PatchFileMatch, bool) {
	for _, match := range matches {
		if match.Filename == name {
			return match, true
		}
	}
	return task.PatchFileMatch{}, false
}

func absMatch(repoPath, rel string) string {
	rel = strings.TrimPrefix(rel, "./")
	if filepath.IsAbs(rel) {
		return rel
	}
	return filepath.Join(repoPath, filepath.FromSlash(rel))
}

func splitLines(body string) []string {
	body = strings.TrimSuffix(body, "\n")
	if body == "" {
		return nil
	}
	return strings.Split(body, "\n")
}
