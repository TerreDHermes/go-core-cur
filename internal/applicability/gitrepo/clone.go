package gitrepo

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Clone creates a temp directory, clones url into it and checks out branch.
// The caller must Remove the returned directory.
// token is sent only to git, as the HTTPS password. An empty token clones without credentials.
func Clone(ctx context.Context, url, branch, token string) (string, error) {
	dir, err := os.MkdirTemp("", "cve-analysis-*")
	if err != nil {
		return "", fmt.Errorf("mkdir temp: %w", err)
	}

	clone := command(ctx, token, cloneArgs(url, dir, token)...)
	if out, err := clone.CombinedOutput(); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("git clone: %w: %s", err, trim(out, token))
	}

	checkout := command(ctx, token, "git", "-C", dir, "checkout", "--quiet", branch)
	if out, err := checkout.CombinedOutput(); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("git checkout %s: %w: %s", branch, err, trim(out, token))
	}
	return dir, nil
}

func cloneArgs(url, dir, token string) []string {
	args := []string{"git"}
	if token != "" {
		// Drop inherited helpers, then read the password from GIT_TOKEN in the child environment.
		// The token value stays out of the process arguments.
		args = append(args,
			"-c", "credential.helper=",
			"-c", `credential.helper=!f() { printf 'username=x-access-token\npassword=%s\n' "$GIT_TOKEN"; }; f`,
		)
	}
	return append(args, "clone", "--quiet", url, dir)
}

func command(ctx context.Context, token string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = gitEnv(token)
	return cmd
}

func Remove(dir string) {
	if dir == "" {
		return
	}
	_ = os.RemoveAll(dir)
}

func gitEnv(token string) []string {
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if token == "" {
		return append(env, "GIT_ASKPASS=echo")
	}
	return append(env, "GIT_TOKEN="+token)
}

func trim(b []byte, token string) string {
	const max = 500
	s := string(b)
	if token != "" {
		s = strings.ReplaceAll(s, token, "[redacted]")
	}
	if len(s) > max {
		return s[:max]
	}
	return s
}
