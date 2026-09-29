package gitrepo

import "context"

// Client is the worker-facing wrapper around Clone and Remove.
// Token comes from GIT_TOKEN. The worker does not see it.
type Client struct {
	Token string
}

func (c Client) Clone(ctx context.Context, url, branch string) (string, error) {
	return Clone(ctx, url, branch, c.Token)
}

func (Client) Remove(dir string) {
	Remove(dir)
}
