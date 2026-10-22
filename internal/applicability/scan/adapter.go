package scan

import (
	"context"
	"strings"

	"cve-patch-viewer/internal/applicability/ai"
	"cve-patch-viewer/internal/applicability/task"
)

type Client struct {
	Patches PatchSource
	AI      Explainer
}

func (c Client) Scan(ctx context.Context, in Input) ([]task.ModuleResult, error) {
	explain := c.AI
	if model := strings.TrimSpace(in.Model); model != "" {
		if client, ok := c.AI.(*ai.AIClient); ok {
			explain = client.WithModel(model)
		}
	}
	return Scan(ctx, in, c.Patches, explain)
}
