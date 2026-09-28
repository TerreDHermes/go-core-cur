package scan

import (
	"context"

	"cveanalysis/internal/task"
)

type Client struct{}

func (Client) Scan(ctx context.Context, in Input) ([]task.ModuleResult, error) {
	return Scan(ctx, in)
}
