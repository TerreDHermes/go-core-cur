package scan

import (
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"cveanalysis/internal/applicability/task"
)

const maxPatchPatterns = 8

var (
	declName = regexp.MustCompile(`\b(?:def|function|func|fn)\s+([A-Za-z_][A-Za-z0-9_]*)`)
	identRe  = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]{3,40}`)
	stringRe = regexp.MustCompile(`"([^"\\]{3,80})"|'([^'\\]{3,80})'`)
)

// patchGrepPatterns pulls a short list of search phrases out of the diff.
// Function names come first, then string literals on changed lines, then
// distinctive identifiers, then file stems. The list is what a non-Go tree is grepped with.
func patchGrepPatterns(patch task.CVEPatch) []string {
	var ranked []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[strings.ToLower(s)] {
			return
		}
		runes := utf8.RuneCountInString(s)
		if runes < minKeywordRunes || runes > maxKeywordRunes {
			return
		}
		if stopword(s) {
			return
		}
		seen[strings.ToLower(s)] = true
		ranked = append(ranked, s)
	}

	for _, file := range patch.Files {
		for _, fn := range functionsInPatch(file.Patch) {
			add(fn.Name)
		}
	}
	var changed, all []string
	for _, file := range patch.Files {
		c, a := patchBodies(file.Patch)
		changed = append(changed, c...)
		all = append(all, a...)
	}
	for _, line := range all {
		for _, m := range declName.FindAllStringSubmatch(line, -1) {
			add(m[1])
		}
	}
	for _, line := range changed {
		for _, m := range stringRe.FindAllStringSubmatch(line, -1) {
			lit := m[1]
			if lit == "" {
				lit = m[2]
			}
			add(lit)
		}
	}
	for _, line := range all {
		for _, tok := range identRe.FindAllString(line, -1) {
			if !distinctiveIdent(tok) {
				continue
			}
			add(tok)
		}
	}
	for _, file := range patch.Files {
		stem := strings.TrimSuffix(path.Base(file.Filename), path.Ext(file.Filename))
		if distinctiveIdent(stem) {
			add(stem)
		}
	}
	if len(ranked) > maxPatchPatterns {
		ranked = ranked[:maxPatchPatterns]
	}
	if ranked == nil {
		ranked = []string{}
	}
	return ranked
}

func patchBodies(diff string) (changed, all []string) {
	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "@@"):
			if i := strings.LastIndex(line, "@@"); i >= 0 {
				all = append(all, line[i+2:])
			}
		case strings.HasPrefix(line, "+++"), strings.HasPrefix(line, "---"), strings.HasPrefix(line, "diff "), strings.HasPrefix(line, "index "):
			continue
		case strings.HasPrefix(line, "+"), strings.HasPrefix(line, "-"):
			body := line[1:]
			changed = append(changed, body)
			all = append(all, body)
		case strings.HasPrefix(line, " "):
			all = append(all, line[1:])
		}
	}
	return changed, all
}

func distinctiveIdent(s string) bool {
	if stopword(s) || utf8.RuneCountInString(s) < minKeywordRunes {
		return false
	}
	if strings.Contains(s, "_") {
		return true
	}
	lower, upper := false, false
	for _, r := range s {
		if unicode.IsLower(r) {
			lower = true
		}
		if unicode.IsUpper(r) {
			upper = true
		}
	}
	return lower && upper
}

func stopword(s string) bool {
	switch strings.ToLower(s) {
	case "true", "false", "none", "null", "nil", "void", "int", "str", "var", "let", "const",
		"func", "function", "def", "class", "public", "private", "static", "import", "from",
		"package", "return", "error", "string", "bytes", "with", "for", "while", "elif", "else",
		"pass", "raise", "throw", "catch", "new", "async", "await", "this", "self", "data",
		"info", "type", "name", "value", "result", "object", "exception", "valueerror",
		"stdout", "stderr", "stdin":
		return true
	default:
		return false
	}
}
