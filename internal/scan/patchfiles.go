package scan

import (
	"os"
	"path"
	"path/filepath"
	"strings"

	"cveanalysis/internal/task"
)

// locatePatchFiles checks every patch file inside vendor/<module>/...
// The patch filename is relative to the git repository that produced the diff.
// The vendor tree is relative to the module directory, so a nested module
// shares a path suffix with the start of the patch filename.
func locatePatchFiles(repoPath, vendorAbs, modulePath string, files []task.PatchFile) []task.PatchFileMatch {
	matches := make([]task.PatchFileMatch, 0, len(files))
	for _, file := range files {
		match := task.PatchFileMatch{Filename: file.Filename}
		if abs, ok := findVendorFile(vendorAbs, modulePath, file.Filename); ok && within(repoPath, abs) {
			if rel, err := filepath.Rel(repoPath, abs); err == nil {
				match.Found = true
				match.Path = "./" + filepath.ToSlash(rel)
			}
		}
		matches = append(matches, match)
	}
	return matches
}

// locateRootPatchFiles checks patch filenames from the cloned repository root.
// Package "root" means the repository under analysis is the project the patch was cut from.
func locateRootPatchFiles(repoPath string, files []task.PatchFile) []task.PatchFileMatch {
	matches := make([]task.PatchFileMatch, 0, len(files))
	for _, file := range files {
		match := task.PatchFileMatch{Filename: file.Filename}
		rel, ok := cleanSlash(file.Filename)
		if !ok {
			matches = append(matches, match)
			continue
		}
		abs := filepath.Join(repoPath, filepath.FromSlash(rel))
		info, err := os.Stat(abs)
		if err == nil && !info.IsDir() && within(repoPath, abs) {
			match.Found = true
			match.Path = "./" + rel
		}
		matches = append(matches, match)
	}
	return matches
}

func foundPaths(matches []task.PatchFileMatch) []string {
	var found []string
	for _, match := range matches {
		if match.Found {
			found = append(found, match.Path)
		}
	}
	return found
}

func findVendorFile(vendorAbs, modulePath, patchFilename string) (string, bool) {
	moduleRel, ok := cleanSlash(modulePath)
	if !ok {
		return "", false
	}
	base := filepath.Join(vendorAbs, filepath.FromSlash(moduleRel))
	for _, rel := range moduleRelCandidates(moduleRel, patchFilename) {
		abs := filepath.Join(base, filepath.FromSlash(rel))
		if !within(base, abs) {
			continue
		}
		info, err := os.Stat(abs)
		if err != nil || info.IsDir() {
			continue
		}
		return abs, true
	}
	return "", false
}

// moduleRelCandidates lists module-relative paths to try, most literal first.
//  1. the patch filename unchanged (module lives at the git root)
//  2. the patch filename with the longest module-path suffix removed
//     (nested module: go.opentelemetry.io/otel/sdk + sdk/resource/host_id.go)
//  3. the remainder after the whole module path, when the patch path embeds it
//     (kubernetes staging: staging/src/k8s.io/client-go/rest/config.go)
func moduleRelCandidates(modulePath, patchFilename string) []string {
	patchRel, ok := cleanSlash(patchFilename)
	if !ok {
		return nil
	}
	rels := []string{patchRel}
	modParts := strings.Split(modulePath, "/")
	patchParts := strings.Split(patchRel, "/")
	for n := len(modParts); n >= 1; n-- {
		if n >= len(patchParts) {
			continue
		}
		suffix := modParts[len(modParts)-n:]
		if hasPrefixParts(patchParts, suffix) {
			rels = appendUnique(rels, path.Join(patchParts[n:]...))
			break
		}
	}
	if idx := indexParts(patchParts, modParts); idx > 0 {
		rest := patchParts[idx+len(modParts):]
		if len(rest) > 0 {
			rels = appendUnique(rels, path.Join(rest...))
		}
	}
	return rels
}

func appendUnique(rels []string, rel string) []string {
	for _, existing := range rels {
		if existing == rel {
			return rels
		}
	}
	return append(rels, rel)
}

func hasPrefixParts(parts, prefix []string) bool {
	if len(prefix) > len(parts) {
		return false
	}
	for i := range prefix {
		if parts[i] != prefix[i] {
			return false
		}
	}
	return true
}

func indexParts(hay, needle []string) int {
	if len(needle) == 0 || len(needle) > len(hay) {
		return -1
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hasPrefixParts(hay[i:], needle) {
			return i
		}
	}
	return -1
}

func cleanSlash(p string) (string, bool) {
	p = path.Clean(filepath.ToSlash(strings.TrimSpace(p)))
	if p == "." || p == ".." || strings.HasPrefix(p, "../") || path.IsAbs(p) {
		return "", false
	}
	return p, true
}

func within(root, target string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
