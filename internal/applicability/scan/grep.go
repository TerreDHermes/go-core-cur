package scan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"cveanalysis/internal/applicability/task"
)

const (
	maxHitsPerPattern = 5
	maxGrepHits       = 25
	maxGrepLineRunes  = 160
	maxGrepFileBytes  = 1 << 20
	excerptBefore     = 12
	excerptAfter      = 24
	maxExcerptLines   = 40
	maxExcerptRunes   = 1200
	maxExcerpts       = 8
)

var errGrepDone = errors.New("grep hit limit reached")

type grepPattern struct {
	text string
	re   *regexp.Regexp
	n    int
}

type grepEvidence struct {
	report task.GrepReport
}

func maybeGrep(ctx context.Context, repoPath string, patch task.CVEPatch, explain Explainer) (*grepEvidence, error) {
	if len(patch.Files) > 0 {
		return nil, nil
	}
	return descriptionGrep(ctx, repoPath, patch, explain)
}

func descriptionGrep(ctx context.Context, repoPath string, patch task.CVEPatch, explain Explainer) (*grepEvidence, error) {
	if explain == nil {
		return nil, fmt.Errorf("ai client is not configured")
	}
	text, err := explain.Explain(ctx, keywordPrompt(patch))
	if err != nil {
		return nil, fmt.Errorf("ai grep phrases: %w", err)
	}
	return grepEvidenceFrom(ctx, repoPath, "description", parseKeywords(text))
}

func patchTreeGrep(ctx context.Context, repoPath string, patch task.CVEPatch) (*grepEvidence, error) {
	patterns := patchGrepPatterns(patch)
	if len(patterns) == 0 {
		return nil, nil
	}
	return grepEvidenceFrom(ctx, repoPath, "patch", patterns)
}

func grepEvidenceFrom(ctx context.Context, repoPath, source string, patterns []string) (*grepEvidence, error) {
	hits, excerpts, truncated, excerptsTruncated, err := grepRepo(ctx, repoPath, patterns)
	if err != nil {
		return nil, err
	}
	return &grepEvidence{report: task.GrepReport{
		Source:            source,
		Patterns:          patterns,
		Hits:              hits,
		Excerpts:          excerpts,
		Truncated:         truncated,
		ExcerptsTruncated: excerptsTruncated,
	}}, nil
}

func applyGrep(result *task.ModuleResult, ev *grepEvidence) {
	if ev == nil {
		return
	}
	copied := ev.report
	result.ReportMD.Grep = &copied
	result.Verdict = strings.TrimSpace(result.Verdict + " " + grepFacts(copied))
}

func withGrep(ctx context.Context, repoPath string, in Input, patch task.CVEPatch, explain Explainer, notes *task.DevNotes, results []task.ModuleResult) ([]task.ModuleResult, error) {
	ev, err := maybeGrep(ctx, repoPath, patch, explain)
	if err != nil {
		return nil, err
	}
	for i := range results {
		applyGrep(&results[i], ev)
	}
	return finish(ctx, in, results, explain, notes)
}

func grepRepo(ctx context.Context, repoPath string, patterns []string) ([]task.GrepHit, []task.GrepExcerpt, bool, bool, error) {
	hits := []task.GrepHit{}
	excerpts := []task.GrepExcerpt{}
	if len(patterns) == 0 {
		return hits, excerpts, false, false, nil
	}
	regs := make([]grepPattern, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(`\b` + regexp.QuoteMeta(pattern) + `\b`)
		if err != nil {
			continue
		}
		regs = append(regs, grepPattern{text: pattern, re: re})
	}
	if len(regs) == 0 {
		return hits, excerpts, false, false, nil
	}
	truncated := false
	excerptsTruncated := false
	err := filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil || info.Size() > maxGrepFileBytes {
			return nil
		}
		more, fileErr := grepFile(repoPath, path, regs, &hits, &excerpts, &truncated, &excerptsTruncated)
		if fileErr != nil {
			return fileErr
		}
		if more {
			return errGrepDone
		}
		return nil
	})
	if err != nil && !errors.Is(err, errGrepDone) {
		return nil, nil, false, false, fmt.Errorf("grep: %w", err)
	}
	return hits, excerpts, truncated, excerptsTruncated, nil
}

func grepFile(repoPath, path string, regs []grepPattern, hits *[]task.GrepHit, excerpts *[]task.GrepExcerpt, truncated, excerptsTruncated *bool) (bool, error) {
	body, err := os.ReadFile(path)
	if err != nil || bytes.IndexByte(body, 0) >= 0 {
		return false, nil
	}
	rel, err := filepath.Rel(repoPath, path)
	if err != nil {
		return false, nil
	}
	rel = "./" + filepath.ToSlash(rel)
	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	goFile := strings.HasSuffix(rel, ".go")
	for idx, line := range lines {
		lineNo := idx + 1
		for i := range regs {
			if !regs[i].re.MatchString(line) {
				continue
			}
			if regs[i].n >= maxHitsPerPattern || len(*hits) >= maxGrepHits {
				*truncated = true
				continue
			}
			regs[i].n++
			*hits = append(*hits, task.GrepHit{
				Pattern: regs[i].text,
				Path:    rel,
				Line:    lineNo,
				Text:    trimGrepLine(line),
			})
			addExcerpt(excerpts, excerptsTruncated, rel, lines, idx, goFile)
		}
		if *truncated && patternsFull(regs) {
			return true, nil
		}
	}
	return false, nil
}

func addExcerpt(excerpts *[]task.GrepExcerpt, excerptsTruncated *bool, path string, lines []string, hitIdx int, goFile bool) {
	lineNo := hitIdx + 1
	for _, excerpt := range *excerpts {
		if excerpt.Path == path && lineNo >= excerpt.From && lineNo <= excerpt.To {
			return
		}
	}
	if len(*excerpts) >= maxExcerpts {
		*excerptsTruncated = true
		return
	}
	from, to := excerptSpan(lines, hitIdx, goFile)
	from, to = shrinkSpan(lines, from, to, hitIdx)
	*excerpts = append(*excerpts, task.GrepExcerpt{
		Path: path,
		From: from + 1,
		To:   to,
		Text: formatExcerpt(lines, from, to),
	})
}

func excerptSpan(lines []string, hitIdx int, goFile bool) (int, int) {
	if goFile {
		if start := findFuncStart(lines, hitIdx); start >= 0 {
			end := funcEnd(lines, start)
			if end-start+1 <= maxExcerptLines {
				return start, end + 1
			}
			return clampWindow(lines, hitIdx, start, end+1)
		}
	}
	return clampWindow(lines, hitIdx, 0, len(lines))
}

func clampWindow(lines []string, hitIdx, lo, hi int) (int, int) {
	if hi > len(lines) {
		hi = len(lines)
	}
	from := hitIdx - excerptBefore
	if from < lo {
		from = lo
	}
	to := hitIdx + excerptAfter + 1
	if to > hi {
		to = hi
	}
	if to-from > maxExcerptLines {
		to = from + maxExcerptLines
		if to > hi {
			to = hi
			from = to - maxExcerptLines
			if from < lo {
				from = lo
			}
		}
	}
	if from > hitIdx {
		from = hitIdx
	}
	if to < hitIdx+1 {
		to = hitIdx + 1
	}
	return from, to
}

func findFuncStart(lines []string, hitIdx int) int {
	low := hitIdx - 120
	if low < 0 {
		low = 0
	}
	for i := hitIdx; i >= low; i-- {
		trimmed := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(trimmed, "func ") && !strings.HasPrefix(trimmed, "func(") {
			continue
		}
		if funcEnd(lines, i) >= hitIdx {
			return i
		}
	}
	return -1
}

func funcEnd(lines []string, start int) int {
	depth := 0
	seen := false
	last := start + 200
	if last >= len(lines) {
		last = len(lines) - 1
	}
	for i := start; i <= last; i++ {
		for _, r := range lines[i] {
			switch r {
			case '{':
				depth++
				seen = true
			case '}':
				if !seen {
					continue
				}
				depth--
				if depth == 0 {
					return i
				}
			}
		}
	}
	return -1
}

func shrinkSpan(lines []string, from, to, hitIdx int) (int, int) {
	for (from < hitIdx || to > hitIdx+1) && excerptRunes(lines, from, to) > maxExcerptRunes {
		if hitIdx-from >= to-(hitIdx+1) && from < hitIdx {
			from++
			continue
		}
		if to > hitIdx+1 {
			to--
			continue
		}
		from++
	}
	return from, to
}

func excerptRunes(lines []string, from, to int) int {
	n := 0
	for i := from; i < to; i++ {
		n += len([]rune(trimExcerptLine(lines[i]))) + 8
	}
	return n
}

func formatExcerpt(lines []string, from, to int) string {
	var b strings.Builder
	for i := from; i < to; i++ {
		fmt.Fprintf(&b, "%d| %s\n", i+1, trimExcerptLine(lines[i]))
	}
	return b.String()
}

func trimExcerptLine(s string) string {
	s = strings.TrimRight(s, "\r")
	r := []rune(s)
	if len(r) <= maxGrepLineRunes {
		return s
	}
	return string(r[:maxGrepLineRunes]) + "…"
}

func patternsFull(regs []grepPattern) bool {
	for _, rg := range regs {
		if rg.n < maxHitsPerPattern {
			return false
		}
	}
	return true
}

func trimGrepLine(s string) string {
	s = strings.TrimSpace(strings.TrimRight(s, "\r"))
	r := []rune(s)
	if len(r) <= maxGrepLineRunes {
		return s
	}
	return string(r[:maxGrepLineRunes]) + "…"
}
