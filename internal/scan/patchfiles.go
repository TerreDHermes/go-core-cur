package scan

import (
	"os"
	"path/filepath"

	"cveanalysis/internal/task"
)

// locatePatchFiles is the first step of the patch pipeline.
// Each patch filename is looked up at vendor/<package>/<file>.
// Later steps (diff comparison, AI) hang off this result and are not implemented yet.
func locatePatchFiles(repoPath, vendorAbs, packageName string, files []task.PatchFile) []string {
	var found []string
	for _, file := range files {
		abs := filepath.Join(vendorAbs, filepath.FromSlash(packageName), filepath.FromSlash(file.Filename))
		info, err := os.Stat(abs)
		if err != nil || info.IsDir() {
			continue
		}
		rel, err := filepath.Rel(repoPath, abs)
		if err != nil {
			continue
		}
		found = append(found, "./"+filepath.ToSlash(rel))
	}
	return found
}
