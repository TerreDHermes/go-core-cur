package scan

import (
	"regexp"
	"strings"

	"cve-patch-viewer/internal/applicability/task"
	"golang.org/x/mod/semver"
)

const (
	versionFixed      = "fixed"
	versionVulnerable = "vulnerable"
	versionUnknown    = "unknown"
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

// versionGate compares each required version with the fixed versions on the same
// major.minor line. A fix on v1.1 or v1.3 does not clear v1.2. The result is fixed
// only when every required version is at least the fix on its own line.
func versionGate(installed string, fixed []string) (status, threshold string) {
	required := splitVersions(installed)
	fixes := canonicalVersions(fixed)
	if len(required) == 0 || len(fixes) == 0 {
		return versionUnknown, ""
	}
	var lines []string
	allFixed := true
	anyVulnerable := false
	for _, raw := range required {
		got, ok := canonicalVersion(raw)
		if !ok {
			allFixed = false
			continue
		}
		fix, ok := lowestFixOnLine(got, fixes)
		if !ok {
			allFixed = false
			continue
		}
		lines = append(lines, fix)
		if semver.Compare(got, fix) < 0 {
			anyVulnerable = true
			allFixed = false
		}
	}
	threshold = strings.Join(uniqueVersions(lines), ", ")
	if allFixed && len(lines) == len(required) {
		return versionFixed, threshold
	}
	if anyVulnerable {
		return versionVulnerable, threshold
	}
	return versionUnknown, ""
}

func fixedVersions(patch task.CVEPatch) []string {
	return append(append([]string{}, patch.FixedVersions...), patch.ProjectInfo.FixedVersions...)
}

func splitVersions(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func canonicalVersions(values []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range values {
		got, ok := canonicalVersion(raw)
		if !ok || seen[got] {
			continue
		}
		seen[got] = true
		out = append(out, got)
	}
	return out
}

func canonicalVersion(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if !strings.HasPrefix(raw, "v") {
		raw = "v" + raw
	}
	if !semver.IsValid(raw) {
		return "", false
	}
	return semver.Canonical(raw), true
}

func lowestFixOnLine(installed string, fixes []string) (string, bool) {
	line := semver.MajorMinor(installed)
	best := ""
	for _, fix := range fixes {
		if semver.MajorMinor(fix) != line {
			continue
		}
		if best == "" || semver.Compare(fix, best) < 0 {
			best = fix
		}
	}
	return best, best != ""
}

func uniqueVersions(values []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range values {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
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
