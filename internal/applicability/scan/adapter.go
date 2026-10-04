package scan

import (
	"context"

	"cveanalysis/internal/applicability/task"
)

type Client struct {
	Patches PatchSource
	AI      Explainer
}

func (c Client) Scan(ctx context.Context, in Input) ([]task.ModuleResult, error) {
	return Scan(ctx, in, c.Patches, c.AI)
}
