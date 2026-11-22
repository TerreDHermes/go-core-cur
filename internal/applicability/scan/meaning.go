package scan

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"cve-patch-viewer/internal/applicability/task"
)

// meaningExcerptLines caps the code slice sent with one file.
// A longer function is cut from the end. A yes that quotes the cut part
// does not count, and the line check stays.
const meaningExcerptLines = 800

// meaningHeavyBlankFiles is how many code files with two or more fragments
// and zero matches turn the model off for the whole patch. A file that
// matched some fragments does not count, and neither does a file the line
// check did not score. A file with a single missed fragment is a lighter
// miss: up to meaningSingleMissFiles of those are still asked, and they
// do not count toward the heavy limit.
const meaningHeavyBlankFiles = 3
const meaningSingleMissFiles = 4

var meaningLineRE = regexp.MustCompile(`(?i)^(?:\d+\s*[:.)]\s*)?(да|нет|несущественно)(?:\s*(?:\||—|–|-)\s*(.*))?$`)

type meaningAnswer struct {
	yes     bool
	trivial bool
	quote   string
}

// refinePatchCheck asks the model about each code file the line check left
// short of a full match. One request asks whether this file shows an attempt
// to land the patch. A yes that quotes a line from the excerpt counts the
// whole file, even when some fragments are missing. A file whose only
// remaining edits do not carry the fix can be counted too, when the model
// points at that edit. Files that already match, and hunks that only edit a
// missing function, are not sent. Three or more files that missed every
// fragment of two or more skip the model for every file. A file with one
// missed fragment does not count toward those three. Up to four such files
// are still asked. More than four are left to the line check, while files
// that already matched something are still asked.
func refinePatchCheck(ctx context.Context, explain Explainer, repoPath string, files []task.PatchFile, report *task.Report) *task.PatchCheck {
	items := collectPatchItems(repoPath, files, report)
	heavy, single := missCounts(repoPath, files, report.PatchFiles)
	if heavy >= meaningHeavyBlankFiles {
		check := summarizePatchItems(items)
		check.Detail += " Смысловая сверка не запускалась: не совпал ни один фрагмент в трёх или больше файлах."
		return check
	}
	skipSingle := single > meaningSingleMissFiles
	for i, file := range files {
		if items[i].status != "partial" || ctx.Err() != nil {
			continue
		}
		if skipSingle && singleMissFile(repoPath, file, report.PatchFiles) {
			continue
		}
		items[i] = reviewPartialFile(ctx, explain, repoPath, file, report.PatchFiles)
	}
	check := summarizePatchItems(items)
	if skipSingle {
		check.Detail += " Файлы, где не найден единственный фрагмент, не сверялись: таких файлов больше четырёх."
	}
	return check
}

// missCounts splits files the line check scored and matched nothing in.
// A single fragment is the light bucket. Two or more fragments are heavy.
func missCounts(repoPath string, files []task.PatchFile, matches []task.PatchFileMatch) (heavy, single int) {
	for _, file := range files {
		if ignoredPatchName(file.Filename) {
			continue
		}
		got := inspectPatchFile(repoPath, file, matches)
		if got.counted == 0 || got.matched > 0 {
			continue
		}
		if got.counted == 1 {
			single++
			continue
		}
		heavy++
	}
	return heavy, single
}

func singleMissFile(repoPath string, file task.PatchFile, matches []task.PatchFileMatch) bool {
	if ignoredPatchName(file.Filename) {
		return false
	}
	got := inspectPatchFile(repoPath, file, matches)
	return got.counted == 1 && got.matched == 0
}

func reviewPartialFile(ctx context.Context, explain Explainer, repoPath string, file task.PatchFile, matches []task.PatchFileMatch) patchItem {
	got := inspectPatchFile(repoPath, file, matches)
	item := patchItem{name: file.Filename, status: got.status, line: got.line}
	if got.status != "partial" || ctx.Err() != nil {
		return item
	}
	var send []int
	for _, idx := range got.unmatched {
		if hunkAddsCode(got.hunks[idx]) {
			send = append(send, idx)
		}
	}
	if len(send) == 0 {
		return item
	}
	_, excerptLines := meaningExcerpt(got.body, got.hunks, send)
	if len(excerptLines) == 0 {
		return item
	}
	note(ctx, "смысловая сверка патча")
	text, err := explain.Explain(ctx, meaningPrompt(file.Filename, renderAskedHunks(got.hunks, send), strings.Join(excerptLines, "\n")))
	if ctx.Err() != nil {
		return item
	}
	if err != nil {
		item.line += ". Смысловая сверка не выполнена"
		return item
	}
	answers := parseMeaning(text)
	if len(answers) == 0 {
		item.line += ". Смысловая сверка не прочитана"
		return item
	}
	attempt := false
	trivial := false
	for _, ans := range answers {
		if ans.yes && quoteInExcerpt(excerptLines, ans.quote) {
			attempt = true
		}
		if ans.trivial && quoteInHunks(got.hunks, send, ans.quote) {
			trivial = true
		}
	}
	if !attempt && !trivial {
		item.line += ". Смысловая сверка не увидела попытку внести патч"
		return item
	}
	_, line := patchedFileLine(file.Filename, got.counted, got.counted, got.ignored)
	if attempt {
		line += ". Смысловая сверка увидела попытку внести патч, которую построчное сравнение не зачло"
	} else {
		line += ". Смысловая сверка посчитала оставшиеся правки несущественными"
	}
	return patchItem{name: file.Filename, status: "full", line: line}
}

func hunkAddsCode(hunk diffHunk) bool {
	for _, line := range hunk.lines {
		if line.added && codeText(line.text) != "" {
			return true
		}
	}
	return false
}

func meaningPrompt(filename, hunksText, code string) string {
	return fmt.Sprintf(`Посмотри на правки и на код. Реши, была ли попытка внести этот патч.

Не каждый фрагмент обязан присутствовать. Имена могут быть другими: код уже могли менять предыдущие патчи. Порядок строк, отступы, пустые строки и комментарии не важны. Соседние строки могут стоять иначе. Сомнение — это «да»: похожая правка считается попыткой внести этот патч.
«Нет» — только когда попытки не видно совсем.

Если оставшиеся правки не несут сути уязвимости — время, дата, штамп генерации, версия в комментарии — это не попытка и не дырка. Ответ тогда «несущественно». Одна настоящая правка — условие, лимит, проверка, вызов — не пустяк: если её попытки не видно, ответ «нет».

Ответ — одна строка и ничего больше:
да | строка из кода, где видна попытка
несущественно | строка из правки, которая не несёт сути
нет

Для «да» после вертикальной черты приведи строку из приведённого кода. Для «несущественно» — строку из приведённых правок. Без этой строки ответ не принимается.

Файл: %s

%s
Код:
%s
`, filename, hunksText, code)
}

func renderAskedHunks(hunks []diffHunk, idxs []int) string {
	var b strings.Builder
	for n, idx := range idxs {
		hunk := hunks[idx]
		fmt.Fprintf(&b, "Фрагмент %d:\n", n+1)
		if hunk.header != "" {
			b.WriteString(hunk.header)
			b.WriteByte('\n')
		}
		for _, line := range hunk.raw {
			b.WriteString(line)
			b.WriteByte('\n')
		}
		if n+1 != len(idxs) {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func quoteInHunks(hunks []diffHunk, idxs []int, quote string) bool {
	var lines []string
	for _, idx := range idxs {
		if idx < 0 || idx >= len(hunks) {
			continue
		}
		if hunks[idx].header != "" {
			lines = append(lines, hunks[idx].header)
		}
		lines = append(lines, hunks[idx].raw...)
	}
	return quoteInExcerpt(lines, quote)
}

func parseMeaning(text string) []meaningAnswer {
	var out []meaningAnswer
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		line = strings.Trim(line, "`")
		m := meaningLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		quote := strings.TrimSpace(m[2])
		quote = strings.Trim(quote, "`")
		word := strings.ToLower(m[1])
		out = append(out, meaningAnswer{
			yes:     word == "да",
			trivial: word == "несущественно",
			quote:   strings.TrimSpace(quote),
		})
	}
	return out
}

func quoteInExcerpt(lines []string, quote string) bool {
	q := compact(codeText(quote))
	if q == "" {
		q = compact(quote)
	}
	if q == "" {
		return false
	}
	for _, line := range lines {
		got := compact(codeText(line))
		if got == "" {
			continue
		}
		if got == q || (len([]rune(q)) >= 12 && strings.Contains(got, q)) {
			return true
		}
	}
	return false
}

func compact(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// meaningExcerpt is the function named in each unmatched hunk. When that
// function is already gone, the excerpt is the functions the hunk adds.
// Declarations above the first function are used when the hunk names nothing
// and adds no function.
func meaningExcerpt(body []string, hunks []diffHunk, idxs []int) (string, []string) {
	var spans [][2]int
	needPrelude := false
	for _, idx := range idxs {
		hunk := hunks[idx]
		if fn, ok := parseFuncDecl(hunk.header); ok {
			if start, end, found := funcSpanLines(body, fn); found {
				spans = append(spans, [2]int{start, end})
				continue
			}
		}
		if added := addedFuncSpans(body, hunk); len(added) > 0 {
			spans = append(spans, added...)
			continue
		}
		needPrelude = true
	}
	if needPrelude {
		if start, end, found := preludeSpan(body); found {
			spans = append(spans, [2]int{start, end})
		}
	}
	spans = mergeSpans(spans)
	var lines []string
	for _, sp := range spans {
		lines = append(lines, body[sp[0]:sp[1]+1]...)
	}
	if len(lines) > meaningExcerptLines {
		lines = lines[:meaningExcerptLines]
	}
	return strings.Join(lines, "\n"), lines
}

// addedFuncSpans is every function the hunk introduces that the file has.
func addedFuncSpans(body []string, hunk diffHunk) [][2]int {
	var spans [][2]int
	seen := map[string]bool{}
	for _, line := range hunk.lines {
		if !line.added {
			continue
		}
		fn, ok := parseFuncDecl(line.text)
		if !ok {
			continue
		}
		label := funcLabel(fn)
		if label == "" || seen[label] {
			continue
		}
		seen[label] = true
		start, end, found := funcSpanLines(body, fn)
		if !found {
			continue
		}
		spans = append(spans, [2]int{start, end})
	}
	return spans
}

func funcSpanLines(lines []string, fn namedFunc) (int, int, bool) {
	for i, line := range lines {
		got, ok := parseFuncDecl(line)
		if !ok || got.Name != fn.Name || got.Recv != fn.Recv {
			continue
		}
		depth := 0
		started := false
		for j := i; j < len(lines); j++ {
			depth, started = braceWalk(lines[j], depth, started)
			if started && depth <= 0 {
				return i, j, true
			}
		}
		return i, len(lines) - 1, true
	}
	return 0, 0, false
}

func preludeSpan(lines []string) (int, int, bool) {
	if len(lines) == 0 {
		return 0, 0, false
	}
	for i, line := range lines {
		if _, ok := parseFuncDecl(line); ok {
			if i == 0 {
				return 0, 0, false
			}
			return 0, i - 1, true
		}
	}
	return 0, len(lines) - 1, true
}

func braceWalk(line string, depth int, started bool) (int, bool) {
	var quote byte
	raw := false
	escaped := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if raw {
			if c == '`' {
				raw = false
			}
			continue
		}
		if quote != 0 {
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
			if c == '`' {
				raw = true
			} else {
				quote = c
			}
			continue
		}
		if c == '/' && i+1 < len(line) && line[i+1] == '/' {
			break
		}
		if c == '{' {
			depth++
			started = true
			continue
		}
		if c == '}' && started {
			depth--
		}
	}
	return depth, started
}

func mergeSpans(spans [][2]int) [][2]int {
	if len(spans) == 0 {
		return nil
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i][0] == spans[j][0] {
			return spans[i][1] < spans[j][1]
		}
		return spans[i][0] < spans[j][0]
	})
	out := [][2]int{spans[0]}
	for _, sp := range spans[1:] {
		last := &out[len(out)-1]
		if sp[0] <= last[1]+1 {
			if sp[1] > last[1] {
				last[1] = sp[1]
			}
			continue
		}
		out = append(out, sp)
	}
	return out
}
