package task

import "strings"

// PatchFileView is one code diff saved with the analysis.
// Path is from the repository root when the file was found in the tree.
// Otherwise it is the path from the patch card.
type PatchFileView struct {
	Path  string `json:"path"`
	Patch string `json:"patch"`
}

// VisiblePatchFiles collects the code diffs stored in the module reports.
// The text comes from the first module that saved that file. A path found
// in the tree wins over the card path. An absolute toolchain path is not
// shown. Markdown, notes and tests are already absent from the stored patch.
func VisiblePatchFiles(modules []ModuleResult) []PatchFileView {
	found := map[string]string{}
	for _, module := range modules {
		for _, match := range module.ReportMD.PatchFiles {
			if !match.Found {
				continue
			}
			if _, ok := found[match.Filename]; ok {
				continue
			}
			if rel := relativePatchPath(match.Path); rel != "" {
				found[match.Filename] = rel
			}
		}
	}
	out := []PatchFileView{}
	seen := map[string]bool{}
	for _, module := range modules {
		for _, file := range module.ReportMD.Patch.Files {
			name := strings.TrimSpace(file.Filename)
			if name == "" || seen[name] || strings.TrimSpace(file.Patch) == "" {
				continue
			}
			seen[name] = true
			path := found[name]
			if path == "" {
				path = relativePatchPath(name)
			}
			if path == "" {
				continue
			}
			out = append(out, PatchFileView{Path: path, Patch: file.Patch})
		}
	}
	return out
}

func relativePatchPath(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.ReplaceAll(raw, "\\", "/")
	if raw == "" || strings.HasPrefix(raw, "/") || windowsPath(raw) {
		return ""
	}
	raw = strings.TrimPrefix(raw, "./")
	raw = strings.TrimPrefix(raw, "/")
	if raw == "" || raw == "." {
		return ""
	}
	return raw
}

func windowsPath(raw string) bool {
	return len(raw) >= 3 && raw[1] == ':' && (raw[2] == '/' || raw[2] == '\\')
}
