package gitrepo

import "context"

// Client is the worker-facing wrapper around Clone and Remove.
type Client struct{}

func (Client) Clone(ctx context.Context, url, branch string) (string, error) {
	return Clone(ctx, url, branch)
}

func (Client) Remove(dir string) {
	Remove(dir)
}
