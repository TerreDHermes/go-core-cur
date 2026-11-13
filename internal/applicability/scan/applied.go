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
			Detail:  "Проверка не проводилась: патч меняет только тестовые файлы или markdown. Файлы _test.go в сверке не учитываются и не доказывают, что уязвимость закрыта. На вывод это не повлияло.",
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
	for _, file := range files {
		if isMarkdown(file.Filename) {
			ignoredMD = true
			lines = append(lines, "файл "+file.Filename+": markdown, в сверке не учитывается")
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
		detail := "Проверка проводилась. Патч применён целиком: все файлы и все фрагменты diff уже есть в коде. Вывод — неприменима."
		if ignoredMD || ignoredTest {
			detail = "Проверка проводилась. Патч применён целиком: все файлы кода и все фрагменты diff уже есть в коде."
			if ignoredMD {
				detail += " Файлы markdown в сверке не учитывались."
			}
			if ignoredTest {
				detail += " Тестовые файлы в сверке не учитывались."
			}
			detail += " Вывод — неприменима."
		}
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
		return "missing", "файл " + file.Filename + " в дереве не найден"
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
		if hunkApplied(lines, hunk.old, hunk.new) {
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
		if isMarkdown(file.Filename) || isTestGo(file.Filename) {
			continue
		}
		sawCode = true
		status, _ := assessPatchFile(repoPath, file, matches)
		if status != "full" {
			return false
		}
	}
	return sawCode
}

func isMarkdown(name string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(name)), ".md")
}

func isTestGo(name string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(name)), "_test.go")
}

func hasCheckedFile(files []task.PatchFile) bool {
	for _, file := range files {
		if !isMarkdown(file.Filename) && !isTestGo(file.Filename) {
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
		lines = append(lines, "файл "+file.Filename+": markdown, в сверке не учитывается")
	}
	return lines
}

type diffHunk struct {
	old []string
	new []string
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
		if line == "" || strings.HasPrefix(line, `\`) {
			continue
		}
		switch line[0] {
		case '+':
			current.new = append(current.new, line[1:])
		case '-':
			current.old = append(current.old, line[1:])
		case ' ':
			current.old = append(current.old, line[1:])
			current.new = append(current.new, line[1:])
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

func hunkApplied(file, oldLines, newLines []string) bool {
	if len(newLines) == 0 && len(oldLines) == 0 {
		return false
	}
	if len(newLines) == 0 {
		return !containsContiguous(file, oldLines)
	}
	at := indexContiguous(file, newLines)
	if at < 0 {
		return false
	}
	return !oldSurvives(file, oldLines, newLines, at)
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

// oldSurvives reports the pre-patch lines still present outside the matched new block.
// A pure insertion keeps the old context inside that block, and that does not count.
func oldSurvives(file, oldLines, newLines []string, newAt int) bool {
	if len(oldLines) == 0 || len(oldLines) > len(file) {
		return false
	}
	end := newAt + len(newLines)
	for i := 0; i <= len(file)-len(oldLines); i++ {
		if !linesEqual(file[i:i+len(oldLines)], oldLines) {
			continue
		}
		if i >= newAt && i+len(oldLines) <= end {
			continue
		}
		return true
	}
	return false
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
