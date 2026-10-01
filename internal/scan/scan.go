package scan

import (
	"context"
	"fmt"

	"cveanalysis/internal/task"
)

type Input struct {
	RepoPath     string
	ComponentURL string
	Branch       string
	CVEID        string
	PackageName  string
}

// PatchSource loads the CVE patch document. The orchestrator calls it once per repository.
type PatchSource interface {
	Fetch(ctx context.Context, cveID string) (task.CVEPatch, error)
}

// Scan chooses one branch of the analysis and does not perform the branch itself.
// A module stops early when it has no vendor or the patch has no files.
// A module with a vendor directory and a patch continues into the patch steps.
func Scan(ctx context.Context, in Input, patches PatchSource) ([]task.ModuleResult, error) {
	paths, err := findGoMods(ctx, in.RepoPath)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return []task.ModuleResult{notGo()}, nil
	}
	if patches == nil {
		return nil, fmt.Errorf("cve patch source is not configured")
	}
	patch, err := patches.Fetch(ctx, in.CVEID)
	if err != nil {
		return nil, fmt.Errorf("cve patch for: %w", err)
	}

	matched, err := modulesWithPackage(ctx, in, paths)
	if err != nil {
		return nil, err
	}
	if len(matched) == 0 {
		return []task.ModuleResult{packageAbsent(in, patch)}, nil
	}

	var found []task.ModuleResult
	for _, mod := range matched {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		found = append(found, analyzeModule(in, patch, mod))
	}
	return found, nil
}

func analyzeModule(in Input, patch task.CVEPatch, mod matchedModule) task.ModuleResult {
	report := task.Report{
		GoModPath:     mod.GoModPath,
		HasVendor:     mod.HasVendor,
		VendorPath:    mod.VendorPath,
		MatchingLines: mod.Lines,
		Patch:         patch,
	}
	if !mod.HasVendor {
		report.Stage = task.StageNoVendor
		return task.ModuleResult{
			GoModPath: mod.GoModPath,
			Verdict:   verdictNoVendor(in, mod.GoModPath, len(patch.Files) == 0),
			ReportMD:  report,
		}
	}
	if len(patch.Files) == 0 {
		report.Stage = task.StageNoPatch
		return task.ModuleResult{
			GoModPath: mod.GoModPath,
			Verdict:   verdictNoPatch(in, mod.GoModPath),
			ReportMD:  report,
		}
	}
	found := locatePatchFiles(in.RepoPath, mod.VendorAbs, in.PackageName, patch.Files)
	report.Stage = task.StagePatchFiles
	report.FoundPatchFiles = found
	return task.ModuleResult{
		GoModPath: mod.GoModPath,
		Verdict:   verdictPatchFiles(in, mod.GoModPath, found),
		ReportMD:  report,
	}
}
