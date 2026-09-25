package scan

import "context"

type Client struct{}

func (Client) Scan(ctx context.Context, in Input) (Result, error) {
	return Scan(ctx, in)
}
