package scan

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cveanalysis/internal/task"
)

type Input struct {
	RepoPath     string
	ComponentURL string
	Branch       string
	CVEID        string
	PackageName  string
}

// PatchSource loads the CVE patch document. Scan calls it once per matching go.mod.
type PatchSource interface {
	Fetch(ctx context.Context, cveID string) (task.CVEPatch, error)
}

// Scan reads every go.mod in the cloned tree. A go.mod becomes a ModuleResult
// only when it lists PackageName. Files that do not mention the package are skipped.
func Scan(ctx context.Context, in Input, patches PatchSource) ([]task.ModuleResult, error) {
	var paths []string
	err := filepath.WalkDir(in.RepoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() && d.Name() == ".git" {
			return fs.SkipDir
		}
		if !d.IsDir() && d.Name() == "go.mod" {
			rel, relErr := filepath.Rel(in.RepoPath, path)
			if relErr != nil {
				return relErr
			}
			paths = append(paths, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("find go.mod: %w", err)
	}
	sort.Strings(paths)

	var found []task.ModuleResult
	for _, rel := range paths {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		body, err := os.ReadFile(filepath.Join(in.RepoPath, filepath.FromSlash(rel)))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", rel, err)
		}
		lines := matchingLines(string(body), in.PackageName)
		if len(lines) == 0 {
			continue
		}
		if patches == nil {
			return nil, fmt.Errorf("cve patch source is not configured")
		}
		patch, err := patches.Fetch(ctx, in.CVEID)
		if err != nil {
			return nil, fmt.Errorf("cve patch for %s: %w", rel, err)
		}
		goModPath := "./" + rel
		hasVendor, vendorPath := vendorBeside(in.RepoPath, rel)
		found = append(found, task.ModuleResult{
			GoModPath: goModPath,
			Verdict:   fmt.Sprintf("%s listed in %s", in.PackageName, goModPath),
			ReportMD: task.Report{
				GoModPath:     goModPath,
				HasVendor:     hasVendor,
				VendorPath:    vendorPath,
				MatchingLines: lines,
				Patch:         patch,
			},
		})
	}
	return found, nil
}

func vendorBeside(repoPath, rel string) (bool, string) {
	modDir := filepath.Dir(filepath.Join(repoPath, filepath.FromSlash(rel)))
	vendorAbs := filepath.Join(modDir, "vendor")
	info, err := os.Stat(vendorAbs)
	if err != nil || !info.IsDir() {
		return false, ""
	}
	relVendor, err := filepath.Rel(repoPath, vendorAbs)
	if err != nil {
		return true, ""
	}
	return true, "./" + filepath.ToSlash(relVendor)
}

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
