package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cve-patch-viewer/internal/applicability/task"
)

// noteAppliedPatch fills the patch-check dossier and, only for a full match,
// marks the vulnerability not applicable.
func noteAppliedPatch(repoPath string, files []task.PatchFile, report *task.Report) string {
	if report == nil {
		return ""
	}
	check := buildPatchCheck(repoPath, files, report)
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

	var lines []string
	var notApplied []string
	allFull := true
	anyFull := false
	anyPartial := false
	ignoredMD := false
	ignoredTest := false
	ignoredAbsent := false
	for _, file := range files {
		if isMarkdown(file.Filename) {
			ignoredMD = true
			lines = append(lines, "файл "+file.Filename+": markdown, в сверке не учитывается")
			continue
		}
		if isTextFile(file.Filename) {
			lines = append(lines, "файл "+file.Filename+": текст, в сверке не учитывается")
			continue
		}
		if isTestGo(file.Filename) {
			ignoredTest = true
			lines = append(lines, "файл "+file.Filename+": тест, в сверке не учитывается")
			continue
		}
		status, line := assessPatchFile(repoPath, file, report.PatchFiles)
		lines = append(lines, line)
		switch status {
		case "full":
			anyFull = true
		case "absent":
			ignoredAbsent = true
		case "partial", "missing":
			allFull = false
			anyPartial = true
			notApplied = append(notApplied, file.Filename)
		default:
			allFull = false
			notApplied = append(notApplied, file.Filename)
		}
	}
	switch {
	case allFull:
		detail := "Проверка проводилась. Патч применён целиком: все файлы и все фрагменты diff уже есть в коде."
		if ignoredMD || ignoredTest || ignoredAbsent {
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
	match, ok := matchByName(matches, file.Filename)
	if diffDeletesFile(file.Patch) {
		if !ok || !match.Found {
			return "full", "файл " + file.Filename + " патч удаляет, и в дереве его нет"
		}
		return "partial", "файл " + file.Filename + " патч удаляет, но он всё ещё в дереве"
	}
	if !ok || !match.Found {
		if diffCreatesFile(file.Patch) {
			return "missing", "файл " + file.Filename + " патч создаёт, но в дереве его нет"
		}
		return "absent", "файл " + file.Filename + " в дереве нет, патч его только правит, в сверке не учитывается"
	}
	if strings.TrimSpace(file.Patch) == "" {
		return "unparsed", "файл " + file.Filename + ": diff пустой, сверить нельзя"
	}
	body, err := os.ReadFile(absMatch(repoPath, match.Path))
	if err != nil {
		return "unparsed", "файл " + file.Filename + " не прочитан"
	}
	hunks, parsed := parseHunks(file.Patch)
	if !parsed || len(hunks) == 0 {
		return "unparsed", "файл " + file.Filename + ": diff не разобран по фрагментам"
	}
	lines := splitLines(string(body))
	matched := 0
	for _, hunk := range hunks {
		if hunkApplied(lines, hunk) {
			matched++
		}
	}
	if matched == len(hunks) {
		return "full", "файл " + file.Filename + ": все фрагменты патча уже в коде"
	}
	return "partial", fmt.Sprintf("файл %s: совпали %d из %d фрагментов", file.Filename, matched, len(hunks))
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
		if status == "absent" {
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
	lines   []hunkLine
	removed []string
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
			current = &diffHunk{}
			continue
		}
		if current == nil {
			if strings.Contains(line, "Binary files") || strings.Contains(line, "GIT binary patch") {
				return nil, false
			}
			continue
		}
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

// patchContextGap is how many code lines around an edit are still the same
// place. The neighbor from the hunk may sit up to three code lines away; a
// matching statement further away is a different function.
const patchContextGap = 4

// hunkApplied reports whether the file already contains this hunk.
// The edit is the tokens the new side adds. They must appear in order, and
// the line must match from its start through the last of those tokens. The
// rest of that line may differ: it is context the patch did not change.
// The nearest unchanged line above and below must still be nearby, so a
// short statement such as total++ does not match a copy in another function.
// Indentation, blank lines and comments are ignored. A removed line cancels
// the match only when it is still in that same window. A pure deletion is
// applied when the removed code is gone from the file.
func hunkApplied(file []string, hunk diffHunk) bool {
	got := codeLines(file)
	block, before, after, removed, ok := editBlock(hunk)
	if !ok {
		if len(removed) > 0 {
			return !containsContiguous(got, removed)
		}
		return true
	}
	return blockMatches(got, block, before, after, removed)
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

func editBlock(hunk diffHunk) (block []linePat, before, after string, removed []string, ok bool) {
	var pieces []codePiece
	for _, line := range hunk.lines {
		text := codeText(line.text)
		if text == "" {
			continue
		}
		pieces = append(pieces, codePiece{text: text, added: line.added})
	}
	start, end := 0, len(pieces)
	for start < end && !pieces[start].added {
		start++
	}
	for end > start && !pieces[end-1].added {
		end--
	}
	removed = codeLines(hunk.removed)
	if start >= end {
		return nil, "", "", removed, false
	}
	if start > 0 {
		before = pieces[start-1].text
	}
	if end < len(pieces) {
		after = pieces[end].text
	}
	var added [][]string
	var addedAt []int
	for _, piece := range pieces[start:end] {
		if !piece.added {
			block = append(block, linePat{text: piece.text})
			continue
		}
		addedAt = append(addedAt, len(block))
		added = append(added, tokenize(piece.text))
		block = append(block, linePat{text: piece.text})
	}
	keep := insertedTokens(removed, added)
	pos := 0
	for n, toks := range added {
		lineKeep := keep[pos : pos+len(toks)]
		pos += len(toks)
		if prefix, drifted := requiredPrefix(toks, lineKeep); drifted {
			block[addedAt[n]] = linePat{prefix: prefix}
		}
	}
	return block, before, after, removed, true
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
