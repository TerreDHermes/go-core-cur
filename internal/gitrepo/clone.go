package gitrepo

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// Clone creates a temp directory, clones url into it and checks out branch.
// The caller must Remove the returned directory.
func Clone(ctx context.Context, url, branch string) (string, error) {
	dir, err := os.MkdirTemp("", "cve-analysis-*")
	if err != nil {
		return "", fmt.Errorf("mkdir temp: %w", err)
	}

	clone := exec.CommandContext(ctx, "git", "clone", "--quiet", url, dir)
	clone.Env = gitEnv()
	if out, err := clone.CombinedOutput(); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("git clone: %w: %s", err, trim(out))
	}

	checkout := exec.CommandContext(ctx, "git", "-C", dir, "checkout", "--quiet", branch)
	checkout.Env = gitEnv()
	if out, err := checkout.CombinedOutput(); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("git checkout %s: %w: %s", branch, err, trim(out))
	}
	return dir, nil
}

func Remove(dir string) {
	if dir == "" {
		return
	}
	_ = os.RemoveAll(dir)
}

func gitEnv() []string {
	return append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=echo",
	)
}

func trim(b []byte) string {
	const max = 500
	s := string(b)
	if len(s) > max {
		return s[:max]
	}
	return s
}
