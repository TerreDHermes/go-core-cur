package scan

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"cveanalysis/internal/task"
)

func verdictPrompt(in Input, report task.Report) string {
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		raw = []byte("{}")
	}
	rules := `Начни абзац ровно с текста ниже и сразу продолжи его после «Все дело в том, что».
Объяснение возьми только из отчёта. Не меняй идентификатор CVE, алиасы, имя компонента, имя пакета и версию.
Достижимость вызовов ещё не проверялась: если файл патча найден, уязвимый код в дереве есть; если все файлы патча отмечены false, уязвимого кода нет.`
	opening := verdictOpening(in, report)
	if report.Reach != nil && report.Reach.Reachable != nil {
		if *report.Reach.Reachable {
			rules = `Файлы патча есть в дереве, и deadcode нашёл путь от main до уязвимой функции.
Верни один абзац и ничего больше: без заголовка, без кавычек вокруг абзаца и без markdown.
Начни его ровно с текста ниже и сразу продолжи после «Все дело в том, что».
Уязвимый код достижим. Не меняй идентификатор CVE, алиасы, имя компонента, имя пакета и версию.`
		} else {
			rules = `Файлы патча есть в дереве, но deadcode не нашёл пути от main до уязвимой функции.
Верни один абзац и ничего больше: без заголовка, без кавычек вокруг абзаца и без markdown.
Начни его ровно с текста ниже и сразу продолжи после «Все дело в том, что».
Уязвимый код недостижим, уязвимости в этой сборке нет. Не меняй идентификатор CVE, алиасы, имя компонента, имя пакета и версию.`
		}
		opening = reachOpening(in, report, *report.Reach.Reachable)
	} else if report.Grep != nil {
		rules = `Патча нет. Реши по полю grep, применима уязвимость или нет.
Верни один абзац и ничего больше: без заголовка, без кавычек вокруг абзаца и без markdown.
Начни его ровно с одного из двух вариантов ниже и сразу продолжи после «Все дело в том, что».
Если совпадения относятся к описанному коду, выбери вариант со словом «применима». Если совпадений нет или они не про этот код, выбери «неприменима».
Поле grep.excerpts — куски файлов вокруг совпадений, с номерами строк. Смотри их, а не только строку совпадения.
Не меняй идентификатор CVE, алиасы, имя компонента, имя пакета и версию. Достижимость вызовов не проверялась.`
		opening = grepChoice(in, report)
	}
	return fmt.Sprintf(`Ты пишешь итоговый вердикт по анализу уязвимости в Go-проекте.
%s

%s

Отчёт:
%s
`, rules, opening, raw)
}

func reachOpening(in Input, report task.Report, reachable bool) string {
	name := componentName(in.ComponentURL)
	label := cveLabel(in.CVEID, report.Patch.Aliases)
	version := report.Version
	if version == "" {
		version = "неизвестна"
	}
	switch {
	case report.FromRoot && reachable:
		return fmt.Sprintf(`Потенциальная уязвимость %s применима к компоненту "%s": файлы патча есть в репозитории и уязвимая функция достижима из main. Все дело в том, что`, label, name)
	case report.FromRoot:
		return fmt.Sprintf(`Потенциальная уязвимость %s неприменима к компоненту "%s": файлы патча есть, но уязвимый код недостижим из main. Все дело в том, что`, label, name)
	case reachable:
		return fmt.Sprintf(`Потенциальная уязвимость %s применима к компоненту "%s", так как используется зависимость "%s" версии "%s", файлы патча найдены и уязвимая функция достижима из main. Все дело в том, что`, label, name, in.PackageName, version)
	default:
		return fmt.Sprintf(`Потенциальная уязвимость %s неприменима к компоненту "%s", хоть и используется зависимость "%s" версии "%s" и файлы патча найдены: уязвимый код недостижим из main. Все дело в том, что`, label, name, in.PackageName, version)
	}
}

func grepChoice(in Input, report task.Report) string {
	name := componentName(in.ComponentURL)
	label := cveLabel(in.CVEID, report.Patch.Aliases)
	version := report.Version
	if version == "" {
		version = "неизвестна"
	}
	switch {
	case report.FromRoot:
		return fmt.Sprintf(`Потенциальная уязвимость %s применима к компоненту "%s": патч не найден, но следы описанного кода в репозитории есть. Все дело в том, что
Потенциальная уязвимость %s неприменима к компоненту "%s": патч не найден и следов описанного кода в репозитории не видно. Все дело в том, что`, label, name, label, name)
	case report.Stage == task.StagePackageAbsent:
		return fmt.Sprintf(`Потенциальная уязвимость %s применима к компоненту "%s", хотя зависимость "%s" в go.mod не найдена: патч не найден, но следы описанного кода в проекте есть. Все дело в том, что
Потенциальная уязвимость %s неприменима к компоненту "%s": зависимость "%s" в go.mod не найдена, патч не найден и следов описанного кода не видно. Все дело в том, что`, label, name, in.PackageName, label, name, in.PackageName)
	default:
		return fmt.Sprintf(`Потенциальная уязвимость %s применима к компоненту "%s", зависимость "%s" версии "%s" указана, патч не найден, но следы описанного кода в проекте есть. Все дело в том, что
Потенциальная уязвимость %s неприменима к компоненту "%s", хоть зависимость "%s" версии "%s" и указана: патч не найден и следов описанного кода в проекте не видно. Все дело в том, что`, label, name, in.PackageName, version, label, name, in.PackageName, version)
	}
}

func verdictOpening(in Input, report task.Report) string {
	name := componentName(in.ComponentURL)
	label := cveLabel(in.CVEID, report.Patch.Aliases)
	version := report.Version
	if version == "" {
		version = "неизвестна"
	}
	switch {
	case report.FromRoot && report.Stage == task.StageNoPatch:
		return fmt.Sprintf(`Потенциальная уязвимость %s пока не оценена для компонента "%s": патч не найден, анализ шёл от корня репозитория. Все дело в том, что`, label, name)
	case report.FromRoot && patchFileFound(report):
		return fmt.Sprintf(`Потенциальная уязвимость %s применима к компоненту "%s". Все дело в том, что`, label, name)
	case report.FromRoot:
		return fmt.Sprintf(`Потенциальная уязвимость %s неприменима к компоненту "%s". Все дело в том, что`, label, name)
	case report.Stage == task.StageNotGo:
		return fmt.Sprintf(`Потенциальная уязвимость %s неприменима к компоненту "%s", потому что проект реализован не на Go. Все дело в том, что`, label, name)
	case report.Stage == task.StagePackageAbsent:
		return fmt.Sprintf(`Потенциальная уязвимость %s неприменима к компоненту "%s", потому что зависимость "%s" ни в одном go.mod не найдена. Все дело в том, что`, label, name, in.PackageName)
	case report.Stage == task.StageNoVendor:
		return fmt.Sprintf(`Потенциальная уязвимость %s пока не оценена для компонента "%s": зависимость "%s" версии "%s" есть в %s, но рядом нет каталога vendor. Все дело в том, что`, label, name, in.PackageName, version, report.GoModPath)
	case report.Stage == task.StageNoPatch:
		return fmt.Sprintf(`Потенциальная уязвимость %s пока не оценена для компонента "%s": зависимость "%s" версии "%s" есть, каталог vendor есть, но патч не найден. Все дело в том, что`, label, name, in.PackageName, version)
	case patchFileFound(report):
		return fmt.Sprintf(`Потенциальная уязвимость %s применима к компоненту "%s", так как используется зависимость "%s" версии "%s". Все дело в том, что`, label, name, in.PackageName, version)
	default:
		return fmt.Sprintf(`Потенциальная уязвимость %s неприменима к компоненту "%s", хоть и используется зависимость "%s" версии "%s". Все дело в том, что`, label, name, in.PackageName, version)
	}
}

func patchFileFound(report task.Report) bool {
	for _, file := range report.PatchFiles {
		if file.Found {
			return true
		}
	}
	return len(report.FoundPatchFiles) > 0
}

func cveLabel(cveID string, aliases []string) string {
	extra := formatAliases(aliases, cveID)
	if extra == "" {
		return cveID
	}
	return cveID + " " + extra
}

func componentName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return raw
	}
	path := strings.TrimSuffix(strings.Trim(parsed.Path, "/"), ".git")
	if i := strings.LastIndex(path, "/"); i >= 0 {
		path = path[i+1:]
	}
	if path == "" {
		return raw
	}
	return path
}
