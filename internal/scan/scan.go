package scan

import (
	"context"
	"fmt"
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

// PatchSource loads the CVE patch document. The orchestrator calls it once per repository.
type PatchSource interface {
	Fetch(ctx context.Context, cveID string) (task.CVEPatch, error)
}

// rootPackage scans the cloned tree itself. The patch paths are already
// relative to that repository, so go.mod and vendor are not consulted.
const rootPackage = "root"

// Explainer writes the final verdict from a prepared prompt.
type Explainer interface {
	Explain(ctx context.Context, prompt string) (string, error)
}

// Scan chooses one branch of the analysis and does not perform the branch itself.
// Package "root" looks for patch files from the repository root.
// Any other package stops a module early when it has no vendor or the patch has no files.
// A module with a vendor directory and a patch continues into the patch steps.
// The deterministic text stays in Report.PreVerdict. Explain replaces Verdict.
func Scan(ctx context.Context, in Input, patches PatchSource, explain Explainer) ([]task.ModuleResult, error) {
	if in.PackageName == rootPackage {
		return scanRoot(ctx, in, patches, explain)
	}
	paths, err := findGoMods(ctx, in.RepoPath)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return finish(ctx, in, []task.ModuleResult{notGo()}, explain)
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
		return finish(ctx, in, []task.ModuleResult{packageAbsent(in, patch)}, explain)
	}

	var found []task.ModuleResult
	for _, mod := range matched {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		found = append(found, analyzeModule(in, patch, mod))
	}
	return finish(ctx, in, found, explain)
}

func analyzeModule(in Input, patch task.CVEPatch, mod matchedModule) task.ModuleResult {
	report := task.Report{
		GoModPath:     mod.GoModPath,
		HasVendor:     mod.HasVendor,
		VendorPath:    mod.VendorPath,
		MatchingLines: mod.Lines,
		Version:       mod.Version,
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
	matches := locatePatchFiles(in.RepoPath, mod.VendorAbs, in.PackageName, patch.Files)
	report.Stage = task.StagePatchFiles
	report.PatchFiles = matches
	report.FoundPatchFiles = foundPaths(matches)
	return task.ModuleResult{
		GoModPath: mod.GoModPath,
		Verdict:   verdictPatchFiles(in, mod.GoModPath, report.FoundPatchFiles),
		ReportMD:  report,
	}
}

func scanRoot(ctx context.Context, in Input, patches PatchSource, explain Explainer) ([]task.ModuleResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if patches == nil {
		return nil, fmt.Errorf("cve patch source is not configured")
	}
	patch, err := patches.Fetch(ctx, in.CVEID)
	if err != nil {
		return nil, fmt.Errorf("cve patch for: %w", err)
	}
	report := task.Report{
		GoModPath: ".",
		FromRoot:  true,
		Patch:     patch,
	}
	if len(patch.Files) == 0 {
		report.Stage = task.StageNoPatch
		return finish(ctx, in, []task.ModuleResult{{
			GoModPath: ".",
			Verdict:   verdictRootNoPatch(),
			ReportMD:  report,
		}}, explain)
	}
	matches := locateRootPatchFiles(in.RepoPath, patch.Files)
	report.Stage = task.StagePatchFiles
	report.PatchFiles = matches
	report.FoundPatchFiles = foundPaths(matches)
	return finish(ctx, in, []task.ModuleResult{{
		GoModPath: ".",
		Verdict:   verdictRootPatchFiles(report.FoundPatchFiles),
		ReportMD:  report,
	}}, explain)
}

func finish(ctx context.Context, in Input, results []task.ModuleResult, explain Explainer) ([]task.ModuleResult, error) {
	if explain == nil {
		return nil, fmt.Errorf("ai client is not configured")
	}
	for i := range results {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		results[i].ReportMD.PreVerdict = results[i].Verdict
		text, err := explain.Explain(ctx, verdictPrompt(in, results[i].ReportMD))
		if err != nil {
			return nil, fmt.Errorf("ai verdict for %s: %w", results[i].GoModPath, err)
		}
		text = strings.TrimSpace(text)
		if text == "" {
			return nil, fmt.Errorf("ai verdict for %s is empty", results[i].GoModPath)
		}
		results[i].Verdict = text
	}
	return results, nil
}
