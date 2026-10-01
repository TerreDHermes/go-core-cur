package scan

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"cveanalysis/internal/task"
)

const (
	maxHitsPerPattern = 5
	maxGrepHits       = 25
	maxGrepLineRunes  = 160
	maxGrepFileBytes  = 1 << 20
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
	if explain == nil {
		return nil, fmt.Errorf("ai client is not configured")
	}
	text, err := explain.Explain(ctx, keywordPrompt(patch))
	if err != nil {
		return nil, fmt.Errorf("ai grep phrases: %w", err)
	}
	patterns := parseKeywords(text)
	hits, truncated, err := grepRepo(ctx, repoPath, patterns)
	if err != nil {
		return nil, err
	}
	return &grepEvidence{report: task.GrepReport{
		Patterns:  patterns,
		Hits:      hits,
		Truncated: truncated,
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

func withGrep(ctx context.Context, repoPath string, in Input, patch task.CVEPatch, explain Explainer, results []task.ModuleResult) ([]task.ModuleResult, error) {
	ev, err := maybeGrep(ctx, repoPath, patch, explain)
	if err != nil {
		return nil, err
	}
	for i := range results {
		applyGrep(&results[i], ev)
	}
	return finish(ctx, in, results, explain)
}

func grepRepo(ctx context.Context, repoPath string, patterns []string) ([]task.GrepHit, bool, error) {
	hits := []task.GrepHit{}
	if len(patterns) == 0 {
		return hits, false, nil
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
		return hits, false, nil
	}
	truncated := false
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
		more, fileErr := grepFile(repoPath, path, regs, &hits, &truncated)
		if fileErr != nil {
			return fileErr
		}
		if more {
			return errGrepDone
		}
		return nil
	})
	if err != nil && !errors.Is(err, errGrepDone) {
		return nil, false, fmt.Errorf("grep: %w", err)
	}
	return hits, truncated, nil
}

func grepFile(repoPath, path string, regs []grepPattern, hits *[]task.GrepHit, truncated *bool) (bool, error) {
	body, err := os.ReadFile(path)
	if err != nil || bytes.IndexByte(body, 0) >= 0 {
		return false, nil
	}
	rel, err := filepath.Rel(repoPath, path)
	if err != nil {
		return false, nil
	}
	rel = "./" + filepath.ToSlash(rel)
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64*1024), 256*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
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
		}
		if *truncated && patternsFull(regs) {
			return true, nil
		}
	}
	return false, nil
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
