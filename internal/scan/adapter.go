package scan

import (
	"context"

	"cveanalysis/internal/task"
)

type Client struct {
	Patches PatchSource
}

func (c Client) Scan(ctx context.Context, in Input) ([]task.ModuleResult, error) {
	return Scan(ctx, in, c.Patches)
}
