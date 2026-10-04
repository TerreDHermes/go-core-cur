package scan

import "strings"

func matchingLines(content, pkg string) []string {
	if strings.TrimSpace(pkg) == "" {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(content, "\n") {
		if tokenPresent(line, pkg) {
			lines = append(lines, strings.TrimSpace(line))
		}
	}
	return lines
}

func tokenPresent(line, pkg string) bool {
	start := 0
	for start < len(line) {
		i := strings.Index(line[start:], pkg)
		if i < 0 {
			return false
		}
		i += start
		end := i + len(pkg)
		beforeOK := i == 0 || !isModuleChar(line[i-1])
		afterOK := end == len(line) || !isModuleChar(line[end])
		if beforeOK && afterOK {
			return true
		}
		start = i + 1
	}
	return false
}

func isModuleChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '.' || b == '/' || b == '-' || b == '_'
}
