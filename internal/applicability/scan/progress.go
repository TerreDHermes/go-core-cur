package scan

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

type progressKey struct{}

// Progress is how far one analysis got. The worker reads it after a deadline
// and puts the same text on the failed task.
type Progress struct {
	mu     sync.Mutex
	stage  string
	detail string
	index  int
	total  int
	goMods int
	known  bool
}

func NewProgress() *Progress { return &Progress{} }

func WithProgress(ctx context.Context, p *Progress) context.Context {
	if p == nil {
		return ctx
	}
	return context.WithValue(ctx, progressKey{}, p)
}

func ProgressFrom(ctx context.Context) *Progress {
	if ctx == nil {
		return nil
	}
	p, _ := ctx.Value(progressKey{}).(*Progress)
	return p
}

func (p *Progress) Stage(name string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.stage = name
	p.detail = ""
	p.index = 0
	p.total = 0
	p.mu.Unlock()
}

func (p *Progress) At(stage, detail string, index, total int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.stage = stage
	p.detail = detail
	p.index = index
	p.total = total
	p.mu.Unlock()
}

func (p *Progress) FoundGoMod() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.goMods++
	p.known = true
	p.mu.Unlock()
}

func (p *Progress) SetGoMods(n int) {
	if p == nil {
		return
	}
	if n < 0 {
		n = 0
	}
	p.mu.Lock()
	p.goMods = n
	p.known = true
	p.mu.Unlock()
}

// Line is the sentence shown in the verdict when the analysis stops.
func (p *Progress) Line() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var b strings.Builder
	if p.stage != "" {
		b.WriteString("Остановились на этапе «")
		b.WriteString(p.stage)
		b.WriteString("»")
		if p.index > 0 && p.total > 0 {
			fmt.Fprintf(&b, ", %d из %d", p.index, p.total)
		}
		if p.detail != "" {
			b.WriteString(" (")
			b.WriteString(p.detail)
			b.WriteString(")")
		}
		b.WriteString(".")
	}
	if p.known {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "Найдено go.mod: %d.", p.goMods)
	}
	return b.String()
}

func (p *Progress) GoMods() (n int, known bool) {
	if p == nil {
		return 0, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.goMods, p.known
}

func note(ctx context.Context, stage string) {
	if p := ProgressFrom(ctx); p != nil {
		p.Stage(stage)
	}
}

func noteAt(ctx context.Context, stage, detail string, index, total int) {
	if p := ProgressFrom(ctx); p != nil {
		p.At(stage, detail, index, total)
	}
}

// swapStage replaces the stage name and keeps the module counter.
// The previous name is restored when a queued deadcode run actually starts.
func swapStage(ctx context.Context, stage string) string {
	p := ProgressFrom(ctx)
	if p == nil {
		return ""
	}
	p.mu.Lock()
	prev := p.stage
	p.stage = stage
	p.mu.Unlock()
	return prev
}
