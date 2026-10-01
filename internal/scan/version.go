package scan

import (
	"regexp"
	"strings"
)

var moduleVersionRe = regexp.MustCompile(`^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:[-+][0-9A-Za-z.-]+)?$`)

// moduleVersion is the version required for pkg in one go.mod.
// A require line wins. exclude and replace are used only when require has no version.
func moduleVersion(content, pkg string) string {
	if strings.TrimSpace(pkg) == "" {
		return ""
	}
	var required, other []string
	seenReq := map[string]bool{}
	seenOther := map[string]bool{}
	inRequire := false
	for _, raw := range strings.Split(content, "\n") {
		line := raw
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == ")" {
			inRequire = false
			continue
		}
		if fields[0] == "require" && len(fields) >= 2 && fields[1] == "(" {
			inRequire = true
			continue
		}
		ver := versionAfter(fields, pkg)
		if ver == "" {
			continue
		}
		if fields[0] == "require" || inRequire {
			if !seenReq[ver] {
				seenReq[ver] = true
				required = append(required, ver)
			}
			continue
		}
		if !seenOther[ver] {
			seenOther[ver] = true
			other = append(other, ver)
		}
	}
	if len(required) > 0 {
		return strings.Join(required, ", ")
	}
	return strings.Join(other, ", ")
}

func versionAfter(fields []string, pkg string) string {
	for i, field := range fields {
		if field != pkg || i+1 >= len(fields) {
			continue
		}
		if moduleVersionRe.MatchString(fields[i+1]) {
			return fields[i+1]
		}
	}
	return ""
}
