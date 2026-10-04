package scan

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"cve-patch-viewer/internal/applicability/task"
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
	if patchFileFound(report) && (report.Reach == nil || report.Reach.Reachable == nil) {
		rules = `Уязвимый код в дереве есть, но установить, входит ли он в работающую программу, не удалось.
Верни один абзац и ничего больше: без заголовка, без кавычек вокруг абзаца и без markdown.
Начни его ровно с текста ниже и сразу продолжи после «Все дело в том, что».
Причину бери из reach.detail и перескажи её как ограничение мнения: сборка не прошла, в программе нет точки входа или вызов установить не удалось. Имена инструментов не называй. Не называй уязвимость применимой и не называй её неприменимой.`
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
Если код в отчёте — это описанная уязвимость, выбери «применима». Если он про другое, выбери «неприменима». Если по коду нельзя понять, та ли это уязвимость, выбери «неопределенна» и напиши, чего не хватает для вывода.
Поле grep.source равно "patch", когда материал взят из diff, и "description", когда из описания.
Поле grep.excerpts — фрагменты кода, по ним и суди. В самом вердикте поля отчёта не называй.
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
Если код в отчёте — это описанная уязвимость, выбери «применима». Если он про другое, выбери «неприменима». Если по коду нельзя понять, та ли это уязвимость, выбери «неопределенна» и напиши, чего не хватает для вывода.
Поле grep.excerpts — фрагменты кода. Смотри их целиком. В самом вердикте поля отчёта не называй.
Не меняй идентификатор CVE, алиасы, имя компонента, имя пакета и версию. Входит ли код в работающую программу, здесь не проверялось.`
		opening = grepChoice(in, report)
	}
	rules += "\nЕсли в отчёте есть dev_notes, учти их в продолжении, когда они относятся к уязвимости. Если поля нет, не упоминай заметки."
	rules += "\nfixed_versions и версию зависимости для вывода не используй. Если уязвимость есть в списке, версия уже считается уязвимой. Решение только по тому, есть ли уязвимый код и входит ли он в программу."
	rules += "\nПродолжение после «Все дело в том, что» — профессиональное мнение: почему вывод именно такой. Пиши о коде и о сути уязвимости. Не описывай процедуру. Нельзя упоминать шаблон, отчёт, поиск, grep, совпадения, паттерны, фразы и то, что начало абзаца задано заранее. Файл или фрагмент кода называй только как обоснование мнения."
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
	return fmt.Sprintf(`Потенциальная уязвимость %s применима к компоненту "%s", хотя проект написан не на Go: описанный уязвимый код в нём есть. Все дело в том, что
Потенциальная уязвимость %s неприменима к компоненту "%s": проект написан не на Go, а похожий код к этой уязвимости не относится. Все дело в том, что
Потенциальная уязвимость %s для компонента "%s" неопределенна: проект не на Go, и по коду нельзя уверенно сказать, что это та самая уязвимость. Все дело в том, что`, label, name, label, name, label, name)
}

func reachUnknownOpening(in Input, report task.Report) string {
	name := componentName(in.ComponentURL)
	label := cveLabel(in.CVEID, report.Patch.Aliases)
	version := report.Version
	if version == "" {
		version = "неизвестна"
	}
	if report.FromRoot {
		return fmt.Sprintf(`Потенциальная уязвимость %s пока не оценена для компонента "%s": уязвимый код в репозитории есть, но нельзя установить, входит ли он в работающую программу. Все дело в том, что`, label, name)
	}
	return fmt.Sprintf(`Потенциальная уязвимость %s пока не оценена для компонента "%s": зависимость "%s" версии "%s" есть, уязвимый код в ней присутствует, но нельзя установить, входит ли он в работающую программу. Все дело в том, что`, label, name, in.PackageName, version)
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
		return fmt.Sprintf(`Потенциальная уязвимость %s неприменима к компоненту "%s": проект не на Go, описанного уязвимого кода в нём нет. Все дело в том, что`, label, name)
	case report.FromRoot:
		return fmt.Sprintf(`Потенциальная уязвимость %s неприменима к компоненту "%s": описанного уязвимого кода в репозитории нет. Все дело в том, что`, label, name)
	default:
		return fmt.Sprintf(`Потенциальная уязвимость %s неприменима к компоненту "%s", зависимость "%s" версии "%s" указана: описанного уязвимого кода в проекте нет. Все дело в том, что`, label, name, in.PackageName, version)
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
		return fmt.Sprintf(`Потенциальная уязвимость %s применима к компоненту "%s": уязвимая функция достижима из main. Все дело в том, что`, label, name)
	case report.FromRoot:
		return fmt.Sprintf(`Потенциальная уязвимость %s неприменима к компоненту "%s": уязвимый код недостижим из main. Все дело в том, что`, label, name)
	case reachable:
		return fmt.Sprintf(`Потенциальная уязвимость %s применима к компоненту "%s", так как используется зависимость "%s" версии "%s" и уязвимая функция достижима из main. Все дело в том, что`, label, name, in.PackageName, version)
	default:
		return fmt.Sprintf(`Потенциальная уязвимость %s неприменима к компоненту "%s", хоть и используется зависимость "%s" версии "%s": уязвимый код недостижим из main. Все дело в том, что`, label, name, in.PackageName, version)
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
		return fmt.Sprintf(`Потенциальная уязвимость %s применима к компоненту "%s": описанный уязвимый код в репозитории есть. Все дело в том, что
Потенциальная уязвимость %s неприменима к компоненту "%s": похожий код к этой уязвимости не относится. Все дело в том, что
Потенциальная уязвимость %s для компонента "%s" неопределенна: по коду нельзя уверенно сказать, что это та самая уязвимость. Все дело в том, что`, label, name, label, name, label, name)
	default:
		return fmt.Sprintf(`Потенциальная уязвимость %s применима к компоненту "%s", зависимость "%s" версии "%s" указана: описанный уязвимый код в проекте есть. Все дело в том, что
Потенциальная уязвимость %s неприменима к компоненту "%s", хоть зависимость "%s" версии "%s" и указана: похожий код к этой уязвимости не относится. Все дело в том, что
Потенциальная уязвимость %s для компонента "%s" неопределенна: зависимость "%s" версии "%s" указана, но по коду нельзя уверенно сказать, что это та самая уязвимость. Все дело в том, что`, label, name, in.PackageName, version, label, name, in.PackageName, version, label, name, in.PackageName, version)
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
		return fmt.Sprintf(`Потенциальная уязвимость %s пока не оценена для компонента "%s": описанного уязвимого кода в репозитории не видно. Все дело в том, что`, label, name)
	case report.FromRoot && patchFileFound(report):
		return fmt.Sprintf(`Потенциальная уязвимость %s применима к компоненту "%s". Все дело в том, что`, label, name)
	case report.FromRoot:
		return fmt.Sprintf(`Потенциальная уязвимость %s неприменима к компоненту "%s". Все дело в том, что`, label, name)
	case report.Stage == task.StageNotGo:
		return fmt.Sprintf(`Потенциальная уязвимость %s пока не оценена для компонента "%s": проект не на Go, и по коду вывод не готов. Все дело в том, что`, label, name)
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
