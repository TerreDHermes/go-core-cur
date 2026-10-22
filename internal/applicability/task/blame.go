package task

import "strings"

// ErrorBlame names who failed a task. The source is chosen from the error text
// we already produce. No model is asked.
type ErrorBlame struct {
	Source string
	Hint   string
}

// BlameError maps a stored error to a party a person can recognize.
// AI HUB is the model gateway. CVE Patch Analyzer is this service.
// The patch service and Git are separate, because those calls leave this process.
func BlameError(msg string) ErrorBlame {
	lower := strings.ToLower(msg)
	if strings.TrimSpace(msg) == "" {
		return ErrorBlame{}
	}
	if isAIHub(lower) {
		switch {
		case strings.Contains(lower, "429") ||
			strings.Contains(lower, "rate_limit") ||
			strings.Contains(lower, "too many requests") ||
			strings.Contains(lower, "admission_queue"):
			return ErrorBlame{Source: "AI HUB", Hint: "AI HUB ограничил запросы: лимит или очередь переполнена."}
		case strings.Contains(lower, "deadline exceeded") || strings.Contains(lower, "timeout"):
			return ErrorBlame{Source: "AI HUB", Hint: "AI HUB не ответил за отведённое время."}
		default:
			return ErrorBlame{Source: "AI HUB", Hint: "Ошибка на стороне AI HUB."}
		}
	}
	if strings.Contains(lower, "cve patch") {
		return ErrorBlame{Source: "Сервис патчей", Hint: "Не удалось получить патч уязвимости."}
	}
	if strings.Contains(lower, "git clone") || strings.Contains(lower, "git checkout") || strings.Contains(lower, "repository url") {
		if strings.Contains(lower, "deadline exceeded") || strings.Contains(lower, "timeout") {
			return ErrorBlame{Source: "Git", Hint: "Репозиторий не скачался за отведённое время."}
		}
		return ErrorBlame{Source: "Git", Hint: "Не удалось получить репозиторий."}
	}
	if strings.Contains(lower, "deadcode") {
		return ErrorBlame{Source: "CVE Patch Analyzer", Hint: "В анализе не найден инструмент deadcode."}
	}
	return ErrorBlame{Source: "CVE Patch Analyzer", Hint: "Ошибка на стороне CVE Patch Analyzer."}
}

func isAIHub(lower string) bool {
	needles := []string{
		"ai api returned",
		"do ai request",
		"ai grep",
		"ai verdict",
		"ai report",
		"ai client",
		"ai base url",
		"ai response",
		"api.ai.sbt",
		"rate_limit",
		"admission_queue",
	}
	for _, needle := range needles {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}
