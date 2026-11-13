package scan

import (
	"context"
	"testing"
)

func TestProgressLineKeepsTheStageAndGoModCount(t *testing.T) {
	p := NewProgress()
	ctx := WithProgress(context.Background(), p)
	note(ctx, "поиск go.mod")
	p.FoundGoMod()
	p.FoundGoMod()
	noteAt(ctx, "проверка достижимости", "example.com/pkg.Func", 2, 8)
	got := p.Line()
	want := "Остановились на этапе «проверка достижимости», 2 из 8 (example.com/pkg.Func). Найдено go.mod: 2."
	if got != want {
		t.Fatal(got)
	}
	n, known := p.GoMods()
	if !known || n != 2 {
		t.Fatalf("%d %v", n, known)
	}
	if prev := swapStage(ctx, "ожидание deadcode"); prev != "проверка достижимости" {
		t.Fatal(prev)
	}
	got = p.Line()
	if got != "Остановились на этапе «ожидание deadcode», 2 из 8 (example.com/pkg.Func). Найдено go.mod: 2." {
		t.Fatal(got)
	}
}
