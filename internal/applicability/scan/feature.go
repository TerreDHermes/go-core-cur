package scan

import (
	"bytes"
	"context"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"cve-patch-viewer/internal/applicability/task"
)

var (
	featureImportRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~/-]*$`)
	featureCallRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`)
)

func needsFeatureCheck(report task.Report) bool {
	return report.Stage == task.StageNoPatch && report.HasVendor && !report.FromRoot
}

func attachFeatureUse(ctx context.Context, repo string, in Input, patch task.CVEPatch, explain Explainer, result *task.ModuleResult) error {
	if explain == nil {
		return fmt.Errorf("ai client is not configured")
	}
	note(ctx, "условие уязвимости")
	text, err := explain.Explain(ctx, featurePrompt(in, patch))
	if err != nil {
		return fmt.Errorf("ai feature condition: %w", err)
	}
	importPath, call, ok := parseFeatureCondition(text)
	feature := task.FeatureReport{Import: importPath, Call: call}
	if !ok {
		feature.Detail = "условие из описания не прочитано, вывод неопределённый"
	} else {
		note(ctx, "зависимости main")
		if err := acquireDeadcode(ctx); err != nil {
			return err
		}
		feature = assessFeature(ctx, moduleDir(repo, result.GoModPath), result.ReportMD.HasVendor, importPath, call)
		releaseDeadcode()
	}
	result.ReportMD.Feature = &feature
	if feature.Detail != "" {
		result.Verdict = strings.TrimSpace(result.Verdict + " " + feature.Detail)
	}
	return nil
}

func featurePrompt(in Input, patch task.CVEPatch) string {
	desc := strings.TrimSpace(patch.Description)
	if ru := strings.TrimSpace(patch.DescriptionRU); ru != "" {
		desc = ru + "\n" + desc
	}
	return fmt.Sprintf(`По описанию уязвимости назови условие, без которого она не работает.
Две строки и ничего больше:
import: <путь импорта пакета Go>
call: <вызов или пусто>

Если дыра в отдельной возможности библиотеки, import — путь этой возможности, уже чем модуль целиком. call — функция, которой приложение её включает, например authz.New.
Если дыра на обычном пути пакета, которым пользуется любой его импорт, import — этот пакет, call оставь пустым.
Не называй общие слова из описания. Не называй модуль целиком, если описание говорит о подпакете или отдельной возможности.
Пакет анализа: %s

Описание:
%s
`, in.PackageName, strings.TrimSpace(desc))
}

func parseFeatureCondition(text string) (importPath, call string, ok bool) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "import:"):
			importPath = strings.TrimSpace(line[len("import:"):])
		case strings.HasPrefix(lower, "call:"):
			call = strings.TrimSpace(line[len("call:"):])
		}
	}
	importPath = strings.Trim(importPath, "`\"'")
	call = strings.Trim(call, "`\"'")
	switch strings.ToLower(call) {
	case "", "-", "пусто", "нет", "none":
		call = ""
	}
	if !featureImportRE.MatchString(importPath) || !strings.Contains(importPath, "/") {
		return "", "", false
	}
	if call != "" && !featureCallRE.MatchString(call) {
		return "", "", false
	}
	return importPath, call, true
}

func moduleDir(repo, goModPath string) string {
	rel := strings.TrimPrefix(goModPath, "./")
	rel = strings.TrimPrefix(rel, "/")
	return filepath.Dir(filepath.Join(repo, filepath.FromSlash(rel)))
}

func assessFeature(ctx context.Context, dir string, useVendor bool, importPath, call string) task.FeatureReport {
	report := task.FeatureReport{Import: importPath, Call: call}
	env := deadcodeEnv(ctx, useVendor)
	graph, err := loadModuleGraph(ctx, dir, env)
	if err != nil {
		if strings.Contains(err.Error(), "не вернул пакеты") {
			report.Detail = "в модуле нет package main, проверить вхождение пакета в программу нельзя"
			return report
		}
		report.Detail = "список пакетов программы не собрался: " + err.Error()
		return report
	}
	mains := mainPackages(graph)
	patterns := mainPatterns(dir, mains)
	if len(patterns) == 0 {
		report.Detail = "в модуле нет package main, проверить вхождение пакета в программу нельзя"
		return report
	}
	deps, err := dependencySet(ctx, dir, env, patterns)
	if err != nil {
		report.Detail = "список пакетов программы не собрался: " + err.Error()
		return report
	}
	if _, ok := deps[importPath]; !ok {
		report.Used = boolPtr(false)
		report.Detail = fmt.Sprintf("пакет %s не входит в сборку main, уязвимость неприменима", importPath)
		return report
	}
	if call == "" {
		report.Used = boolPtr(true)
		report.Detail = fmt.Sprintf("пакет %s входит в сборку, уязвимость на обычном пути этого пакета, уязвимость применима", importPath)
		return report
	}
	found, err := featureCallUsed(dir, importPath, call)
	if err != nil {
		report.Detail = "вызов в коде приложения проверить не удалось: " + err.Error()
		return report
	}
	if !found {
		report.Used = boolPtr(false)
		report.Detail = fmt.Sprintf("пакет %s входит в сборку, но вызов %s в коде приложения не найден, уязвимость неприменима", importPath, call)
		return report
	}
	report.Used = boolPtr(true)
	report.Detail = fmt.Sprintf("пакет %s входит в сборку и код приложения вызывает %s, уязвимость применима", importPath, call)
	return report
}

func featureCallUsed(moduleDir, importPath, call string) (bool, error) {
	funcName := call
	if i := strings.LastIndex(call, "."); i >= 0 {
		funcName = call[i+1:]
	}
	if funcName == "" {
		return false, nil
	}
	var found bool
	err := filepath.WalkDir(moduleDir, func(file string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if found || !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil || info.Size() > maxGrepFileBytes {
			return nil
		}
		src, err := os.ReadFile(file)
		if err != nil {
			return nil
		}
		if !bytes.Contains(src, []byte(importPath)) || !bytes.Contains(src, []byte(funcName)) {
			return nil
		}
		local, dot, ok := localImportName(file, src, importPath)
		if !ok {
			return nil
		}
		var re *regexp.Regexp
		if dot {
			re = regexp.MustCompile(`\b` + regexp.QuoteMeta(funcName) + `\w*\s*\(`)
		} else {
			re = regexp.MustCompile(`\b` + regexp.QuoteMeta(local) + `\.` + regexp.QuoteMeta(funcName) + `\w*\b`)
		}
		if re.Match(src) {
			found = true
		}
		return nil
	})
	return found, err
}

func localImportName(filename string, src []byte, importPath string) (name string, dot bool, ok bool) {
	file, err := parser.ParseFile(token.NewFileSet(), filename, src, parser.ImportsOnly)
	if err != nil {
		return "", false, false
	}
	for _, imp := range file.Imports {
		got, err := strconv.Unquote(imp.Path.Value)
		if err != nil || got != importPath {
			continue
		}
		if imp.Name != nil {
			switch imp.Name.Name {
			case "_":
				return "", false, false
			case ".":
				return "", true, true
			default:
				return imp.Name.Name, false, true
			}
		}
		return path.Base(importPath), false, true
	}
	return "", false, false
}

func boolPtr(v bool) *bool {
	return &v
}
