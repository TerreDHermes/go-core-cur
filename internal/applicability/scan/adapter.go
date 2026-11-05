package scan

import (
	"context"

	"cve-patch-viewer/internal/applicability/ai"
	"cve-patch-viewer/internal/applicability/task"
)

type Client struct {
	Patches PatchSource
	AI      Explainer
}

func (c Client) Scan(ctx context.Context, in Input) ([]task.ModuleResult, error) {
	explain := c.AI
	var fb *modelFallback
	if client, ok := c.AI.(*ai.AIClient); ok {
		fb = newModelFallback(client, in.Model)
		explain = fb
	}
	results, err := Scan(ctx, in, c.Patches, explain)
	if fb != nil {
		fb.stamp(results)
	}
	return results, err
}
