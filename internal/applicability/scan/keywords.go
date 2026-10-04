package scan

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"cveanalysis/internal/applicability/task"
)

const (
	maxGrepPatterns = 5
	minKeywordRunes = 3
	maxKeywordRunes = 80
)

func keywordPrompt(patch task.CVEPatch) string {
	return fmt.Sprintf(`По описанию уязвимости выпиши ровно 5 строк для поиска по исходному коду, как для команды grep -rwn.
Каждая строка — одна фраза: имя функции, имя типа, строка ошибки, название библиотеки или компонента.
Без нумерации, без маркеров, без кавычек и без пояснений.
Не короче 3 символов. Если в описании мало имён, добавь от себя только те идентификаторы, которые прямо следуют из этого текста.

Описание:
%s

Описание на русском:
%s
`, patch.Description, patch.DescriptionRU)
}

func parseKeywords(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = cleanKeyword(line)
		runes := utf8.RuneCountInString(line)
		if line == "" || runes < minKeywordRunes || runes > maxKeywordRunes {
			continue
		}
		key := strings.ToLower(line)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, line)
		if len(out) == maxGrepPatterns {
			break
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

func cleanKeyword(line string) string {
	line = strings.TrimSpace(line)
	line = strings.Trim(line, "`\"'")
	line = strings.TrimLeftFunc(line, func(r rune) bool {
		return r == '-' || r == '*' || r == '•' || r == ' ' || r == '\t'
	})
	for i := 1; i <= 2 && i < len(line); i++ {
		if line[i] != '.' && line[i] != ')' {
			continue
		}
		digits := true
		for _, r := range line[:i] {
			if r < '0' || r > '9' {
				digits = false
				break
			}
		}
		if digits {
			line = strings.TrimSpace(line[i+1:])
		}
		break
	}
	return strings.Trim(strings.TrimSpace(line), "`\"'")
}
