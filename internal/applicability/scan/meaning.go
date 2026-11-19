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

var meaningLineRE = regexp.MustCompile(`(?i)^\s*(\d+)\s*[:.)]\s*(да|нет)(?:\s*(?:\||—|–|-)\s*(.*))?$`)

type meaningAnswer struct {
	yes   bool
	quote string
}

// refinePatchCheck asks the model about each code file the line check left
// short of a full match. One request carries every unmatched addition of that
// file. Files that already match, and hunks that only edit a missing function,
// are not sent.
func refinePatchCheck(ctx context.Context, explain Explainer, repoPath string, files []task.PatchFile, report *task.Report) *task.PatchCheck {
	items := collectPatchItems(repoPath, files, report)
	for i, file := range files {
		if items[i].status != "partial" || ctx.Err() != nil {
			continue
		}
		items[i] = reviewPartialFile(ctx, explain, repoPath, file, report.PatchFiles)
	}
	return summarizePatchItems(items)
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
	confirmed := 0
	for n, idx := range send {
		ans, ok := answers[n+1]
		if !ok || !ans.yes {
			continue
		}
		if !quoteInExcerpt(excerptLines, ans.quote) || !quoteShowsAddition(got.hunks[idx], ans.quote) {
			continue
		}
		confirmed++
	}
	if confirmed == 0 {
		item.line += ". Смысловая сверка не нашла оставшиеся фрагменты в коде"
		return item
	}
	got.matched += confirmed
	status, line := patchedFileLine(file.Filename, got.matched, got.counted, got.ignored)
	if got.matched == got.counted {
		line += ". Смысловая сверка подтвердила фрагменты, которые построчное сравнение не зачло"
	} else {
		line += fmt.Sprintf(". Смысловая сверка подтвердила ещё %d", confirmed)
	}
	return patchItem{name: file.Filename, status: status, line: line}
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
	return fmt.Sprintf(`Для каждого фрагмента реши, есть ли эта правка в коде ниже.

Порядок строк не важен. Отступы, пустые строки и комментарии не важны. Соседние строки могут стоять иначе. Хвост строки, который правка не меняла, может называться иначе. Это всё та же правка.
Другой способ закрыть ту же ошибку этой правкой не считается.

Ответ — по одной строке на фрагмент и ничего больше:
1: да | строка из кода, в которой правка видна
1: нет

Номер — номер фрагмента. Для «да» после вертикальной черты приведи строку из приведённого кода. Без этой строки ответ не принимается.

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

func parseMeaning(text string) map[int]meaningAnswer {
	out := map[int]meaningAnswer{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		line = strings.Trim(line, "`")
		m := meaningLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		n := 0
		for _, c := range m[1] {
			n = n*10 + int(c-'0')
		}
		if n <= 0 {
			continue
		}
		quote := strings.TrimSpace(m[3])
		quote = strings.Trim(quote, "`")
		out[n] = meaningAnswer{yes: strings.EqualFold(m[2], "да"), quote: strings.TrimSpace(quote)}
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

// quoteShowsAddition requires every newly inserted token of one added line
// to sit in the quote. A neighboring line the patch did not change does not pass.
func quoteShowsAddition(hunk diffHunk, quote string) bool {
	got := map[string]bool{}
	for _, tok := range tokenize(codeText(quote)) {
		got[tok] = true
	}
	for _, fresh := range freshTokensByLine(hunk) {
		if len(fresh) == 0 {
			continue
		}
		all := true
		for _, tok := range fresh {
			if !got[tok] {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func freshTokensByLine(hunk diffHunk) [][]string {
	var added [][]string
	for _, line := range hunk.lines {
		if !line.added {
			continue
		}
		text := codeText(line.text)
		if text == "" {
			continue
		}
		added = append(added, tokenize(text))
	}
	if len(added) == 0 {
		return nil
	}
	keep := insertedTokens(codeLines(hunk.removed), added)
	var out [][]string
	pos := 0
	for _, toks := range added {
		if pos+len(toks) > len(keep) {
			break
		}
		var fresh []string
		lineKeep := keep[pos : pos+len(toks)]
		pos += len(toks)
		for i, tok := range toks {
			if !lineKeep[i] {
				fresh = append(fresh, tok)
			}
		}
		if len(fresh) > 0 {
			out = append(out, fresh)
		}
	}
	return out
}

// meaningExcerpt is the function named in each unmatched hunk, or the
// declarations above the first function when the hunk has no function name.
func meaningExcerpt(body []string, hunks []diffHunk, idxs []int) (string, []string) {
	var spans [][2]int
	needPrelude := false
	for _, idx := range idxs {
		fn, ok := parseFuncDecl(hunks[idx].header)
		if !ok {
			needPrelude = true
			continue
		}
		start, end, found := funcSpanLines(body, fn)
		if !found {
			needPrelude = true
			continue
		}
		spans = append(spans, [2]int{start, end})
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
