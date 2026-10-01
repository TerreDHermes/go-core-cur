package scan

import (
	"fmt"
	"strings"

	"cveanalysis/internal/task"
)

func notGo() task.ModuleResult {
	return task.ModuleResult{
		GoModPath: "-",
		Verdict:   "Не было найдено ни одного go.mod. В связи с этим, сделаем вывод, что проект реализован не на языке go. Анализ возможен только проектов на языке golang.",
		ReportMD:  task.Report{Stage: task.StageNotGo},
	}
}

func packageAbsent(in Input, patch task.CVEPatch) task.ModuleResult {
	return task.ModuleResult{
		GoModPath: "-",
		Verdict: fmt.Sprintf(
			"Потенциальная уязвимость %s %s не применима, так как пакет %s ни в каком go.mod не найден. Если это пакет не гошный, тогда данный вывод не актуален и стоит провести анализ самостоятельно. Если пакет гошный, тогда, возможно, в названии есть опечатка.",
			in.CVEID, formatAliases(patch.Aliases, in.CVEID), in.PackageName,
		),
		ReportMD: task.Report{Stage: task.StagePackageAbsent, Patch: patch},
	}
}

func verdictNoVendor(in Input, goModPath string, patchMissing bool) string {
	verdict := fmt.Sprintf("Пакет %s действительно есть в %s. Но рядом директории vendor нет. В связи с этим, анализ для текущего go.mod завершен - без vendor анализ невозможен.", in.PackageName, goModPath)
	if patchMissing {
		verdict += " Патч тоже не найден."
	}
	return verdict
}

func verdictNoPatch(in Input, goModPath string) string {
	return fmt.Sprintf("Пакет %s действительно есть в %s. И рядом с ним лежит директория vendor. Но патч не найден.", in.PackageName, goModPath)
}

func verdictPatchFiles(in Input, goModPath string, found []string) string {
	verdict := fmt.Sprintf("Пакет %s действительно есть в %s. И рядом с ним лежит директория vendor.", in.PackageName, goModPath)
	if len(found) == 0 {
		return verdict + " Ни один файл патча в vendor не найден."
	}
	return verdict + " В vendor найдены файлы патча: " + strings.Join(found, ", ") + "."
}

func verdictRootNoPatch() string {
	return "Пакет указан как root, поэтому go.mod не искался. Анализ идёт от корня репозитория. Но патч не найден."
}

func grepFacts(g task.GrepReport) string {
	list := strings.Join(g.Patterns, ", ")
	if list == "" {
		list = "(фразы не выделены)"
	}
	text := fmt.Sprintf("Для поиска по проекту выбраны фразы: %s. Совпадений сохранено: %d.", list, len(g.Hits))
	if g.Truncated {
		text += " Список совпадений обрезан до фиксированного размера."
	}
	return text
}

func verdictRootPatchFiles(found []string) string {
	verdict := "Пакет указан как root, поэтому go.mod не искался. Файлы патча искались от корня репозитория."
	if len(found) == 0 {
		return verdict + " Ни один файл патча в корне не найден."
	}
	return verdict + " В корне найдены файлы патча: " + strings.Join(found, ", ") + "."
}

func formatAliases(ids []string, cveID string) string {
	var aliases string
	for _, id := range ids {
		if id == cveID {
			continue
		}
		if len(aliases) == 0 {
			aliases = id
			continue
		}
		aliases = aliases + ", " + id
	}
	if len(aliases) == 0 {
		return ""
	}
	return "(" + aliases + ")"
}
