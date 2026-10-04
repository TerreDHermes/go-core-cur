package scan

import (
	"context"
	"fmt"
	"strings"

	"cve-patch-viewer/internal/applicability/task"
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

// Explainer writes the final verdict and the analysis journal.
type Explainer interface {
	Explain(ctx context.Context, prompt string) (string, error)
}

// Scan chooses one branch of the analysis and does not perform the branch itself.
// dapp/README.md is read first when that file exists.
// Package "root" looks for patch files from the repository root.
// A repository with no go.mod is not treated as finished: the patch is fetched and the tree is grepped.
// Any other package stops a module early when it has no vendor and the patch has files.
// A module with a vendor directory and a patch continues into the patch steps.
// An empty patch asks the model for five grep phrases, searches the tree, and stores both.
// The deterministic text stays in Report.PreVerdict. Explain replaces Verdict and fills Narrative.
func Scan(ctx context.Context, in Input, patches PatchSource, explain Explainer) ([]task.ModuleResult, error) {
	notes, err := loadDevNotes(in.RepoPath)
	if err != nil {
		return nil, err
	}
	if in.PackageName == rootPackage {
		return scanRoot(ctx, in, patches, explain, notes)
	}
	paths, err := findGoMods(ctx, in.RepoPath)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return scanNotGo(ctx, in, patches, explain, notes)
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
		return finish(ctx, in, []task.ModuleResult{packageAbsent(in, patch)}, explain, notes)
	}

	var found []task.ModuleResult
	for _, mod := range matched {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		found = append(found, analyzeModule(ctx, in, patch, mod))
	}
	return withGrep(ctx, in.RepoPath, in, patch, explain, notes, found)
}

func scanNotGo(ctx context.Context, in Input, patches PatchSource, explain Explainer, notes *task.DevNotes) ([]task.ModuleResult, error) {
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
	result := task.ModuleResult{
		GoModPath: "-",
		ReportMD:  task.Report{Stage: task.StageNotGo, Patch: patch},
	}
	var ev *grepEvidence
	if len(patch.Files) > 0 {
		ev, err = patchTreeGrep(ctx, in.RepoPath, patch)
		if err != nil {
			return nil, err
		}
		if ev == nil {
			ev, err = descriptionGrep(ctx, in.RepoPath, patch, explain)
			if err != nil {
				return nil, err
			}
			result.Verdict = verdictNotGo(len(patch.Files), false)
		} else {
			result.Verdict = verdictNotGo(len(patch.Files), true)
		}
	} else {
		ev, err = descriptionGrep(ctx, in.RepoPath, patch, explain)
		if err != nil {
			return nil, err
		}
		result.Verdict = verdictNotGo(0, false)
	}
	applyGrep(&result, ev)
	return finish(ctx, in, []task.ModuleResult{result}, explain, notes)
}

func analyzeModule(ctx context.Context, in Input, patch task.CVEPatch, mod matchedModule) task.ModuleResult {
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
	verdict := verdictPatchFiles(in, mod.GoModPath, report.FoundPatchFiles)
	if patchFileFound(report) {
		report.Reach = analyzeReach(ctx, in.RepoPath, patch.Files, report.PatchFiles)
		verdict += reachFacts(report.Reach)
	}
	return task.ModuleResult{
		GoModPath: mod.GoModPath,
		Verdict:   verdict,
		ReportMD:  report,
	}
}

func scanRoot(ctx context.Context, in Input, patches PatchSource, explain Explainer, notes *task.DevNotes) ([]task.ModuleResult, error) {
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
		return withGrep(ctx, in.RepoPath, in, patch, explain, notes, []task.ModuleResult{{
			GoModPath: ".",
			Verdict:   verdictRootNoPatch(),
			ReportMD:  report,
		}})
	}
	matches := locateRootPatchFiles(in.RepoPath, patch.Files)
	report.Stage = task.StagePatchFiles
	report.PatchFiles = matches
	report.FoundPatchFiles = foundPaths(matches)
	verdict := verdictRootPatchFiles(report.FoundPatchFiles)
	if patchFileFound(report) {
		report.Reach = analyzeReach(ctx, in.RepoPath, patch.Files, report.PatchFiles)
		verdict += reachFacts(report.Reach)
	}
	return finish(ctx, in, []task.ModuleResult{{
		GoModPath: ".",
		Verdict:   verdict,
		ReportMD:  report,
	}}, explain, notes)
}

func finish(ctx context.Context, in Input, results []task.ModuleResult, explain Explainer, notes *task.DevNotes) ([]task.ModuleResult, error) {
	if explain == nil {
		return nil, fmt.Errorf("ai client is not configured")
	}
	attachNotes(results, notes)
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
		kind := decideApplicability(results[i].ReportMD, text)
		results[i].Applicability = kind
		results[i].ReportMD.Applicability = kind
		narrative, err := explain.Explain(ctx, narrativePrompt(in, results[i].ReportMD, text))
		if err != nil {
			return nil, fmt.Errorf("ai report for %s: %w", results[i].GoModPath, err)
		}
		narrative = strings.TrimSpace(narrative)
		if narrative == "" {
			return nil, fmt.Errorf("ai report for %s is empty", results[i].GoModPath)
		}
		results[i].ReportMD.Narrative = narrative
	}
	return results, nil
}
