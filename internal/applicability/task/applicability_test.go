package task

import "testing"

func TestClassifyVerdict(t *testing.T) {
	cases := []struct {
		text string
		want string
	}{
		{"Потенциальная уязвимость CVE-1 применима к компоненту.", Applicable},
		{"Потенциальная уязвимость CVE-1 неприменима к компоненту.", NotApplicable},
		{"Потенциальная уязвимость не применима, пакет не найден.", NotApplicable},
		{"Уязвимость пока не оценена для компонента.", Uncertain},
		{"Вывод неопределенный.", Uncertain},
		{"model-verdict", Uncertain},
		{"Сначала применима, потом слово неприменима не меняет начала.", Applicable},
	}
	for _, tc := range cases {
		if got := ClassifyVerdict(tc.text); got != tc.want {
			t.Fatalf("%q: got %s want %s", tc.text, got, tc.want)
		}
	}
}

func TestRollupApplicability(t *testing.T) {
	mod := func(kind string) ModuleResult { return ModuleResult{Applicability: kind} }
	if got := RollupApplicability(nil); got != Uncertain {
		t.Fatal(got)
	}
	if got := RollupApplicability([]ModuleResult{mod(NotApplicable), mod(NotApplicable)}); got != NotApplicable {
		t.Fatal(got)
	}
	if got := RollupApplicability([]ModuleResult{mod(NotApplicable), mod(Uncertain)}); got != Uncertain {
		t.Fatal(got)
	}
	if got := RollupApplicability([]ModuleResult{mod(NotApplicable), mod(Applicable)}); got != Applicable {
		t.Fatal(got)
	}
}

func TestDurationMS(t *testing.T) {
	pending := Task{Status: StatusPending, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z"}
	if ms := pending.DurationMS(); ms == nil || *ms != 0 {
		t.Fatalf("%v", ms)
	}
	done := Task{Status: StatusCompleted, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:04Z"}
	if ms := done.DurationMS(); ms == nil || *ms != 4000 {
		t.Fatalf("%v", ms)
	}
	if (Task{Status: StatusRunning}).DurationMS() != nil {
		t.Fatal("missing stamps")
	}
	if done.PublicApplicability() == nil || *done.PublicApplicability() != Uncertain {
		t.Fatal(done.PublicApplicability())
	}
	if pending.PublicApplicability() != nil {
		t.Fatal(pending.PublicApplicability())
	}
}
