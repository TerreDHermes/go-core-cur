package scan

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"cveanalysis/internal/applicability/task"
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
	if report.VersionStatus == versionFixed {
		rules = `Версия зависимости уже содержит исправление на своей линии релиза. Код после этого не разбирался.
Верни один абзац и ничего больше: без заголовка, без кавычек вокруг абзаца и без markdown.
Начни его ровно с текста ниже и сразу продолжи после «Все дело в том, что».
Уязвимость неприменима из-за версии. Не меняй идентификатор CVE, алиасы, имя компонента, имя пакета и версии.`
		opening = versionFixedOpening(in, report)
	} else if patchFileFound(report) && (report.Reach == nil || report.Reach.Reachable == nil) {
		rules = `Файлы патча найдены, но проверка досягаемости не дала ответа: анализ не доведён.
Верни один абзац и ничего больше: без заголовка, без кавычек вокруг абзаца и без markdown.
Начни его ровно с текста ниже и сразу продолжи после «Все дело в том, что».
Причину бери из reach.detail. Не называй уязвимость применимой и не называй её неприменимой.`
		opening = reachUnknownOpening(in, report)
	} else if report.Grep != nil && len(report.Grep.Hits) == 0 {
		rules = `Поиск по дереву не нашёл ни одного совпадения. Следов описанного кода нет.
Верни один абзац и ничего больше: без заголовка, без кавычек вокруг абзаца и без markdown.
Начни его ровно с текста ниже и сразу продолжи после «Все дело в том, что».
Уязвимость неприменима. Не меняй идентификатор CVE, алиасы, имя компонента, имя пакета и версию.`
		opening = grepNoneOpening(in, report)
	} else if report.Stage == task.StageNotGo && report.Grep != nil {
		rules = `Проект не на Go: go.mod нет, deadcode не запускался. Реши по полю grep и по dev_notes, если они есть.
Верни один абзац и ничего больше: без заголовка, без кавычек вокруг абзаца и без markdown.
Начни его ровно с одного из трёх вариантов ниже и сразу продолжи после «Все дело в том, что».
Если совпадения и куски файлов относятся к описанному коду, выбери «применима». Если они не про этот код, выбери «неприменима». Если совпадения есть, но по кускам файлов нельзя понять, тот ли это код, выбери «неопределенна» и напиши, почему нельзя понять.
Поле grep.source равно "patch", когда фразы взяты из diff, и "description", когда из описания.
Поле grep.excerpts — куски файлов вокруг совпадений, с номерами строк.
Не меняй идентификатор CVE, алиасы и имя компонента.`
		opening = notGoChoice(in, report)
	} else if report.Reach != nil && report.Reach.Reachable != nil {
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
		rules = `Патча нет. Реши по полю grep.
Верни один абзац и ничего больше: без заголовка, без кавычек вокруг абзаца и без markdown.
Начни его ровно с одного из трёх вариантов ниже и сразу продолжи после «Все дело в том, что».
Если совпадения и куски файлов относятся к описанному коду, выбери «применима». Если они не про этот код, выбери «неприменима». Если совпадения есть, но по кускам файлов нельзя понять, тот ли это код, выбери «неопределенна» и напиши, почему нельзя понять.
Поле grep.excerpts — куски файлов вокруг совпадений, с номерами строк. Смотри их, а не только строку совпадения.
Не меняй идентификатор CVE, алиасы, имя компонента, имя пакета и версию. Достижимость вызовов не проверялась.`
		opening = grepChoice(in, report)
	}
	rules += "\nЕсли в отчёте есть dev_notes, учти их в продолжении, когда они относятся к уязвимости. Если поля нет, не упоминай заметки."
	return fmt.Sprintf(`Ты пишешь итоговый вердикт по анализу уязвимости в проекте.
%s

%s

Отчёт:
%s
`, rules, opening, raw)
}

func notGoChoice(in Input, report task.Report) string {
	name := componentName(in.ComponentURL)
	label := cveLabel(in.CVEID, report.Patch.Aliases)
	return fmt.Sprintf(`Потенциальная уязвимость %s применима к компоненту "%s", хотя проект написан не на Go: следы описанного кода в дереве есть. Все дело в том, что
Потенциальная уязвимость %s неприменима к компоненту "%s": проект написан не на Go и найденные совпадения не про этот код. Все дело в том, что
Потенциальная уязвимость %s для компонента "%s" неопределенна: проект не на Go, совпадения есть, но по ним не видно, тот ли это уязвимый код. Все дело в том, что`, label, name, label, name, label, name)
}

func versionFixedOpening(in Input, report task.Report) string {
	name := componentName(in.ComponentURL)
	label := cveLabel(in.CVEID, report.Patch.Aliases)
	return fmt.Sprintf(`Потенциальная уязвимость %s неприменима к компоненту "%s", так как зависимость "%s" версии "%s" уже не ниже исправления "%s" на той же линии релиза. Все дело в том, что`, label, name, in.PackageName, report.Version, report.FixedVersion)
}

func reachUnknownOpening(in Input, report task.Report) string {
	name := componentName(in.ComponentURL)
	label := cveLabel(in.CVEID, report.Patch.Aliases)
	version := report.Version
	if version == "" {
		version = "неизвестна"
	}
	if report.FromRoot {
		return fmt.Sprintf(`Потенциальная уязвимость %s пока не оценена для компонента "%s": файлы патча найдены, но проверка досягаемости не дала ответа. Все дело в том, что`, label, name)
	}
	return fmt.Sprintf(`Потенциальная уязвимость %s пока не оценена для компонента "%s": зависимость "%s" версии "%s" есть и файлы патча найдены, но проверка досягаемости не дала ответа. Все дело в том, что`, label, name, in.PackageName, version)
}

func grepNoneOpening(in Input, report task.Report) string {
	name := componentName(in.ComponentURL)
	label := cveLabel(in.CVEID, report.Patch.Aliases)
	version := report.Version
	if version == "" {
		version = "неизвестна"
	}
	switch {
	case report.Stage == task.StageNotGo:
		return fmt.Sprintf(`Потенциальная уязвимость %s неприменима к компоненту "%s": проект не на Go, поиск по дереву не нашёл следов описанного кода. Все дело в том, что`, label, name)
	case report.FromRoot:
		return fmt.Sprintf(`Потенциальная уязвимость %s неприменима к компоненту "%s": патч не найден и следов описанного кода в репозитории не видно. Все дело в том, что`, label, name)
	default:
		return fmt.Sprintf(`Потенциальная уязвимость %s неприменима к компоненту "%s", зависимость "%s" версии "%s" указана: патч не найден и следов описанного кода в проекте не видно. Все дело в том, что`, label, name, in.PackageName, version)
	}
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
Потенциальная уязвимость %s неприменима к компоненту "%s": патч не найден и найденные совпадения не про этот код. Все дело в том, что
Потенциальная уязвимость %s для компонента "%s" неопределенна: патч не найден, совпадения есть, но по ним не видно, тот ли это уязвимый код. Все дело в том, что`, label, name, label, name, label, name)
	default:
		return fmt.Sprintf(`Потенциальная уязвимость %s применима к компоненту "%s", зависимость "%s" версии "%s" указана, патч не найден, но следы описанного кода в проекте есть. Все дело в том, что
Потенциальная уязвимость %s неприменима к компоненту "%s", хоть зависимость "%s" версии "%s" и указана: патч не найден и найденные совпадения не про этот код. Все дело в том, что
Потенциальная уязвимость %s для компонента "%s" неопределенна: зависимость "%s" версии "%s" указана, патч не найден, совпадения есть, но по ним не видно, тот ли это уязвимый код. Все дело в том, что`, label, name, in.PackageName, version, label, name, in.PackageName, version, label, name, in.PackageName, version)
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
		return fmt.Sprintf(`Потенциальная уязвимость %s пока не оценена для компонента "%s": проект не на Go, а поиск по дереву не сохранён. Все дело в том, что`, label, name)
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
