package scan

import (
	"os"
	"path/filepath"
	"strings"

	"cve-patch-viewer/internal/applicability/task"
)

// noteAppliedPatch records a fully applied diff only after reachability is true.
// Anything short of every file and every hunk leaves the report unchanged.
func noteAppliedPatch(repoPath string, files []task.PatchFile, report *task.Report) string {
	if report == nil || report.Reach == nil || report.Reach.Reachable == nil || !*report.Reach.Reachable {
		return ""
	}
	if !patchFullyApplied(repoPath, files, report.PatchFiles) {
		return ""
	}
	report.PatchApplied = &task.PatchApplied{
		Applied: true,
		Detail:  "все файлы и все фрагменты патча уже есть в коде",
	}
	return " Патч применён целиком: уязвимого кода в этой версии уже нет."
}

func patchFullyApplied(repoPath string, files []task.PatchFile, matches []task.PatchFileMatch) bool {
	if len(files) == 0 {
		return false
	}
	for _, file := range files {
		match, ok := matchByName(matches, file.Filename)
		if !ok {
			return false
		}
		if diffDeletesFile(file.Patch) {
			if match.Found {
				return false
			}
			continue
		}
		if !match.Found || strings.TrimSpace(file.Patch) == "" {
			return false
		}
		body, err := os.ReadFile(absMatch(repoPath, match.Path))
		if err != nil {
			return false
		}
		hunks, ok := parseHunks(file.Patch)
		if !ok || len(hunks) == 0 {
			return false
		}
		lines := splitLines(string(body))
		for _, hunk := range hunks {
			if !hunkApplied(lines, hunk.old, hunk.new) {
				return false
			}
		}
	}
	return true
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
	return filepath.Join(repoPath, filepath.FromSlash(rel))
}

func splitLines(body string) []string {
	body = strings.TrimSuffix(body, "\n")
	if body == "" {
		return nil
	}
	return strings.Split(body, "\n")
}
