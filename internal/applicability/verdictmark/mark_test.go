package verdictmark

import (
	"strings"
	"testing"
)

func TestStampWritesTheSignAfterTheFirstPeriodAndAtTheEnd(t *testing.T) {
	text := `Уязвимость неприменима к компоненту "app". Все дело в том, что патч уже есть.`
	got := Stamp(text)
	first := strings.Index(text, ".")
	if first < 0 || !strings.HasPrefix(got[first+1:], Mark) {
		t.Fatalf("sign is not after the first period: %q", got)
	}
	if !strings.HasSuffix(got, Mark) || strings.Count(got, Mark) != 2 {
		t.Fatalf("sign count %d text %q", strings.Count(got, Mark), got)
	}
	if Stamp(got) != got {
		t.Fatal("stamping twice changed the text")
	}
}

func TestStampWritesTheSignOnceWhenTheVerdictIsOneSentence(t *testing.T) {
	got := Stamp("Уязвимость неприменима.")
	if got != "Уязвимость неприменима."+Mark || strings.Count(got, Mark) != 1 {
		t.Fatalf("%q", got)
	}
}

func TestStampSkipsAVersionDot(t *testing.T) {
	text := "В стандартной библиотеке Go 1.22.5 уязвимого кода нет. Патч уже лежит в дереве."
	got := Stamp(text)
	version := strings.Index(got, "1.22.5")
	if version < 0 || strings.Contains(got[version:version+len("1.22.5")], Mark) {
		t.Fatalf("version was split: %q", got)
	}
	end := strings.Index(text, "нет.")
	if !strings.HasPrefix(got[end+len("нет."):], Mark) {
		t.Fatalf("first sentence was missed: %q", got)
	}
	if strings.Count(got, Mark) != 2 {
		t.Fatalf("%q", got)
	}
}

func TestStampTreatsQuestionAndEllipsisAsASentence(t *testing.T) {
	question := Stamp("Это та уязвимость? Да, она применима.")
	if !strings.HasPrefix(question[strings.Index(question, "?"):][1:], Mark) || strings.Count(question, Mark) != 2 {
		t.Fatalf("%q", question)
	}
	dots := Stamp("Код совпал... Дальше вывод.")
	if !strings.HasPrefix(dots[strings.Index(dots, "..."):][3:], Mark) {
		t.Fatalf("%q", dots)
	}
}

func TestStampPutsTheSignAtTheEndWhenThereIsNoSentence(t *testing.T) {
	if got := Stamp("  без точки  "); got != "без точки"+Mark {
		t.Fatalf("%q", got)
	}
	if Stamp("") != "" || Stamp("   ") != "" {
		t.Fatal("empty text")
	}
}

func TestCountSeparatesOurTexts(t *testing.T) {
	ours, foreign := Count([]string{
		Stamp("Уязвимость неприменима."),
		"Этот абзац написан в другом месте.",
		Stamp(`Первое предложение. Второе.`),
		"",
	})
	if ours != 2 || foreign != 2 {
		t.Fatalf("ours %d foreign %d", ours, foreign)
	}
	if Ours("чужой текст") || !Ours(Stamp("Наш.")) {
		t.Fatal("ours check")
	}
}
