package scan

import (
	"context"
	"strings"

	"cve-patch-viewer/internal/applicability/ai"
	"cve-patch-viewer/internal/applicability/task"
)

const (
	reserveQwen = "Qwen/Qwen3.6-35B-A3B"
	reserveGiga = "GigaChat-2-Pro"
)

// modelFallback retries one prompt when the model's admission queue is full.
// The next calls of the same analysis stay on the model that answered.
type modelFallback struct {
	client  *ai.AIClient
	initial string
	model   string
	tried   map[string]bool
	notes   []string
}

func newModelFallback(client *ai.AIClient, requested string) *modelFallback {
	model := strings.TrimSpace(requested)
	if model == "" && client != nil {
		model = strings.TrimSpace(client.Model)
	}
	return &modelFallback{
		client:  client,
		initial: model,
		model:   model,
		tried:   map[string]bool{},
	}
}

func (f *modelFallback) Explain(ctx context.Context, prompt string) (string, error) {
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		text, err := f.client.WithModel(f.model).Explain(ctx, prompt)
		if err == nil || !ai.AdmissionQueueFull(err) {
			return text, err
		}
		f.tried[f.model] = true
		next := nextReserve(f.model, f.tried)
		if next == "" {
			return "", err
		}
		f.notes = append(f.notes, "Модель сменена с "+f.model+" на "+next+": очередь AI HUB переполнена.")
		f.model = next
	}
}

func (f *modelFallback) stamp(results []task.ModuleResult) {
	if f == nil || len(f.notes) == 0 {
		return
	}
	note := strings.Join(f.notes, "\n")
	for i := range results {
		results[i].ReportMD.ModelNote = note
		results[i].ReportMD.ActiveModel = f.model
	}
}

// nextReserve tries Qwen first, then GigaChat. A model that already returned
// the queue error is not tried again.
func nextReserve(current string, tried map[string]bool) string {
	if current != reserveQwen && !tried[reserveQwen] {
		return reserveQwen
	}
	if current != reserveGiga && !tried[reserveGiga] {
		return reserveGiga
	}
	return ""
}
