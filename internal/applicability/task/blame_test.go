package task

import "testing"

func TestBlameError(t *testing.T) {
	cases := []struct {
		msg    string
		source string
		hint   string
	}{
		{
			`AI grep phrases: AI API returned 429: {"error":{"message":"Access denied. Request count limit exceeded","type":"rate_limit_error"}}`,
			"AI HUB",
			"AI HUB ограничил запросы: лимит или очередь переполнена.",
		},
		{
			`ai grep phrases: AI API returned 429: {"error":{"type":"Too Many Requests","code":"admission_queue_full","message":"admission queue is at capacity"}}`,
			"AI HUB",
			"AI HUB ограничил запросы: лимит или очередь переполнена.",
		},
		{
			`ai report for ./go.mod: do AI request: Post "https://api.ai.sbt/openai/v1/chat/completions": context deadline exceeded`,
			"AI HUB",
			"AI HUB не ответил за отведённое время.",
		},
		{"cve patch CVE-1: status 502", "Сервис патчей", "Не удалось получить патч уязвимости."},
		{"git clone: exit status 128: authentication failed", "Git", "Не удалось получить репозиторий."},
		{"git checkout release: context deadline exceeded", "Git", "Репозиторий не скачался за отведённое время."},
		{"бинарник deadcode не найден в PATH", "CVE Patch Analyzer", "В анализе не найден инструмент deadcode."},
		{"panic: runtime error", "CVE Patch Analyzer", "Ошибка на стороне CVE Patch Analyzer."},
		{"", "", ""},
	}
	for _, tc := range cases {
		got := BlameError(tc.msg)
		if got.Source != tc.source || got.Hint != tc.hint {
			t.Fatalf("%q:\n got %#v\nwant %s / %s", tc.msg, got, tc.source, tc.hint)
		}
	}
}
