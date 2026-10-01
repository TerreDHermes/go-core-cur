package scan

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

func findGoMods(ctx context.Context, repoPath string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, err error) error {
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
			rel, relErr := filepath.Rel(repoPath, path)
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
	return paths, nil
}

type matchedModule struct {
	GoModPath  string
	Lines      []string
	Version    string
	HasVendor  bool
	VendorPath string
	VendorAbs  string
}

func modulesWithPackage(ctx context.Context, in Input, paths []string) ([]matchedModule, error) {
	var matched []matchedModule
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
		hasVendor, vendorPath, vendorAbs := vendorBeside(in.RepoPath, rel)
		matched = append(matched, matchedModule{
			GoModPath:  "./" + rel,
			Lines:      lines,
			Version:    moduleVersion(string(body), in.PackageName),
			HasVendor:  hasVendor,
			VendorPath: vendorPath,
			VendorAbs:  vendorAbs,
		})
	}
	return matched, nil
}

func vendorBeside(repoPath, rel string) (bool, string, string) {
	modDir := filepath.Dir(filepath.Join(repoPath, filepath.FromSlash(rel)))
	vendorAbs := filepath.Join(modDir, "vendor")
	info, err := os.Stat(vendorAbs)
	if err != nil || !info.IsDir() {
		return false, "", ""
	}
	relVendor, err := filepath.Rel(repoPath, vendorAbs)
	if err != nil {
		return true, "", vendorAbs
	}
	return true, "./" + filepath.ToSlash(relVendor), vendorAbs
}
