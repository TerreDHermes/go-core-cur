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
	Model        string
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
// Package "stdlib" reads the Go release from each go.mod and checks that toolchain, not vendor.
// Package "root" looks for patch files from the repository root and does not also scan modules.
// Any other package still checks those root paths when the patch lists files, and keeps a hit as its own result.
// A repository with no go.mod is not treated as finished: the patch is fetched and the tree is grepped.
// A named package missing from every go.mod is not a finished "not applicable": the tree is searched too.
// Any other package stops a module early when it has no vendor and the patch has files.
// A module with a vendor directory and a patch continues into the patch steps.
// An empty patch asks the model for five grep phrases, searches the tree, and stores both.
// A reachable patch is not applicable only when every hunk is already present.
// The deterministic text stays in Report.PreVerdict. Explain replaces Verdict and fills Narrative.
func Scan(ctx context.Context, in Input, patches PatchSource, explain Explainer) ([]task.ModuleResult, error) {
	note(ctx, "чтение заметок")
	notes, err := loadDevNotes(in.RepoPath)
	if err != nil {
		return nil, err
	}
	if in.PackageName == rootPackage {
		return scanRoot(ctx, in, patches, explain, notes)
	}
	if isStdlib(in.PackageName) {
		return scanStdlib(ctx, in, patches, explain, notes)
	}
	paths, err := findGoMods(ctx, in.RepoPath)
	if err != nil {
		return nil, err
	}
	if p := ProgressFrom(ctx); p != nil {
		p.SetGoMods(len(paths))
	}
	if len(paths) == 0 {
		return scanNotGo(ctx, in, patches, explain, notes)
	}
	if patches == nil {
		return nil, fmt.Errorf("cve patch source is not configured")
	}
	note(ctx, "загрузка патча")
	patch, err := patches.Fetch(ctx, in.CVEID)
	if err != nil {
		return nil, fmt.Errorf("cve patch for: %w", err)
	}

	note(ctx, "чтение go.mod")
	matched, err := modulesWithPackage(ctx, in, paths)
	if err != nil {
		return nil, err
	}
	if len(matched) == 0 {
		if hit, ok := rootHit(ctx, in.RepoPath, patch, false); ok {
			return finish(ctx, in, []task.ModuleResult{hit}, explain, notes)
		}
		return searchAbsent(ctx, in, patch, explain, notes)
	}

	var found []task.ModuleResult
	for i, mod := range matched {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		noteAt(ctx, "разбор модуля", mod.GoModPath, i+1, len(matched))
		found = append(found, analyzeModule(ctx, in, patch, mod))
	}
	if hit, ok := rootHit(ctx, in.RepoPath, patch, false); ok {
		found = append(found, hit)
	}
	return withGrep(ctx, in.RepoPath, in, patch, explain, notes, found)
}

func scanNotGo(ctx context.Context, in Input, patches PatchSource, explain Explainer, notes *task.DevNotes) ([]task.ModuleResult, error) {
	if p := ProgressFrom(ctx); p != nil {
		p.SetGoMods(0)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	note(ctx, "загрузка патча")
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
	result.Verdict += noteAppliedPatch(in.RepoPath, patch.Files, &result.ReportMD)
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
		result := task.ModuleResult{
			GoModPath: mod.GoModPath,
			Verdict:   verdictNoVendor(in, mod.GoModPath, len(patch.Files) == 0),
			ReportMD:  report,
		}
		result.Verdict += noteAppliedPatch(in.RepoPath, patch.Files, &result.ReportMD)
		return result
	}
	if len(patch.Files) == 0 {
		report.Stage = task.StageNoPatch
		result := task.ModuleResult{
			GoModPath: mod.GoModPath,
			Verdict:   verdictNoPatch(in, mod.GoModPath),
			ReportMD:  report,
		}
		result.Verdict += noteAppliedPatch(in.RepoPath, patch.Files, &result.ReportMD)
		return result
	}
	matches := locatePatchFiles(in.RepoPath, mod.VendorAbs, in.PackageName, patch.Files)
	report.Stage = task.StagePatchFiles
	report.PatchFiles = matches
	report.FoundPatchFiles = foundPaths(matches)
	verdict := verdictPatchFiles(in, mod.GoModPath, report.FoundPatchFiles)
	verdict += attachReach(ctx, in.RepoPath, patch, &report)
	result := task.ModuleResult{
		GoModPath: mod.GoModPath,
		Verdict:   verdict,
		ReportMD:  report,
	}
	result.Verdict += noteAppliedPatch(in.RepoPath, patch.Files, &result.ReportMD)
	return result
}

func scanRoot(ctx context.Context, in Input, patches PatchSource, explain Explainer, notes *task.DevNotes) ([]task.ModuleResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	note(ctx, "загрузка патча")
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
		result := task.ModuleResult{
			GoModPath: ".",
			Verdict:   verdictRootNoPatch(),
			ReportMD:  report,
		}
		result.Verdict += noteAppliedPatch(in.RepoPath, patch.Files, &result.ReportMD)
		return withGrep(ctx, in.RepoPath, in, patch, explain, notes, []task.ModuleResult{result})
	}
	if hit, ok := rootHit(ctx, in.RepoPath, patch, true); ok {
		return finish(ctx, in, []task.ModuleResult{hit}, explain, notes)
	}
	matches := locateRootPatchFiles(in.RepoPath, patch.Files)
	report.Stage = task.StagePatchFiles
	report.PatchFiles = matches
	report.FoundPatchFiles = foundPaths(matches)
	result := task.ModuleResult{
		GoModPath: ".",
		Verdict:   verdictRootPatchFiles(report.FoundPatchFiles),
		ReportMD:  report,
	}
	result.Verdict += noteAppliedPatch(in.RepoPath, patch.Files, &result.ReportMD)
	return finish(ctx, in, []task.ModuleResult{result}, explain, notes)
}

func rootHit(ctx context.Context, repoPath string, patch task.CVEPatch, explicit bool) (task.ModuleResult, bool) {
	if len(patch.Files) == 0 {
		return task.ModuleResult{}, false
	}
	matches := locateRootPatchFiles(repoPath, patch.Files)
	found := foundPaths(matches)
	if len(found) == 0 {
		return task.ModuleResult{}, false
	}
	report := task.Report{
		GoModPath:       ".",
		FromRoot:        true,
		Stage:           task.StagePatchFiles,
		Patch:           patch,
		PatchFiles:      matches,
		FoundPatchFiles: found,
	}
	verdict := verdictRootPatchFiles(found)
	if !explicit {
		verdict = verdictExtraRoot(found)
	}
	verdict += attachReach(ctx, repoPath, patch, &report)
	result := task.ModuleResult{GoModPath: ".", Verdict: verdict, ReportMD: report}
	result.Verdict += noteAppliedPatch(repoPath, patch.Files, &result.ReportMD)
	return result, true
}

func attachReach(ctx context.Context, repoPath string, patch task.CVEPatch, report *task.Report) string {
	if !patchFileFound(*report) {
		return ""
	}
	report.Reach = analyzeReach(ctx, repoPath, patch.Files, report.PatchFiles)
	return reachFacts(report.Reach)
}

func searchAbsent(ctx context.Context, in Input, patch task.CVEPatch, explain Explainer, notes *task.DevNotes) ([]task.ModuleResult, error) {
	result := task.ModuleResult{
		GoModPath: "-",
		Verdict: fmt.Sprintf(
			"Пакет %s ни в одном go.mod не найден. Это может быть опечатка в имени или код не на Go, поэтому дерево репозитория проверено отдельно.",
			in.PackageName,
		),
		ReportMD: task.Report{Stage: task.StagePackageAbsent, Patch: patch},
	}
	var ev *grepEvidence
	var err error
	if len(patch.Files) > 0 {
		ev, err = patchTreeGrep(ctx, in.RepoPath, patch)
		if err != nil {
			return nil, err
		}
	}
	if ev == nil {
		ev, err = descriptionGrep(ctx, in.RepoPath, patch, explain)
		if err != nil {
			return nil, err
		}
	}
	applyGrep(&result, ev)
	result.Verdict += noteAppliedPatch(in.RepoPath, patch.Files, &result.ReportMD)
	return finish(ctx, in, []task.ModuleResult{result}, explain, notes)
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
		noteAt(ctx, "вердикт модели", results[i].GoModPath, i+1, len(results))
		results[i].ReportMD.PreVerdict = results[i].Verdict
		text, err := explain.Explain(ctx, verdictPrompt(in, results[i].ReportMD))
		if err != nil {
			return nil, fmt.Errorf("ai verdict for %s: %w", results[i].GoModPath, err)
		}
		text = ensureVerdictLead(verdictLead(in, results[i].ReportMD), text)
		text = withPartialPatchNote(text, results[i].ReportMD)
		if text == "" {
			return nil, fmt.Errorf("ai verdict for %s is empty", results[i].GoModPath)
		}
		results[i].Verdict = text
		kind := decideApplicability(results[i].ReportMD, text)
		results[i].Applicability = kind
		results[i].ReportMD.Applicability = kind
		noteAt(ctx, "журнал модели", results[i].GoModPath, i+1, len(results))
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
