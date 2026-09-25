package scan

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

type Input struct {
	RepoPath     string
	ComponentURL string
	Branch       string
	CVEID        string
	PackageName  string
}

type Result struct {
	Verdict  string
	ReportMD string
}

// Scan walks the cloned tree and collects every go.mod path, the same set
// `find ./ -name go.mod` would print.
func Scan(ctx context.Context, in Input) (Result, error) {
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
			paths = append(paths, "./"+filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("find go.mod: %w", err)
	}
	sort.Strings(paths)

	var b strings.Builder
	fmt.Fprintf(&b, "# go.mod paths\n\n")
	fmt.Fprintf(&b, "- CVE: `%s`\n", in.CVEID)
	fmt.Fprintf(&b, "- Package: `%s`\n", in.PackageName)
	fmt.Fprintf(&b, "- Repository: `%s`\n", in.ComponentURL)
	fmt.Fprintf(&b, "- Branch: `%s`\n\n", in.Branch)
	if len(paths) == 0 {
		b.WriteString("No go.mod files found.\n")
	} else {
		for _, p := range paths {
			b.WriteString(p)
			b.WriteByte('\n')
		}
	}

	return Result{
		Verdict:  fmt.Sprintf("found %d go.mod", len(paths)),
		ReportMD: b.String(),
	}, nil
}
