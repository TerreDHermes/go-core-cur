package gitrepo

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

// Clone creates a temp directory, clones url into it and checks out branch.
// The caller must Remove the returned directory.
// token is the HTTPS password from GIT_TOKEN. An SSH URL is cloned over HTTPS so the
// same token is used. An empty token clones the URL as given, without credentials.
func Clone(ctx context.Context, rawURL, branch, token string) (string, error) {
	remote, err := cloneURL(rawURL, token)
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "cve-analysis-*")
	if err != nil {
		return "", fmt.Errorf("mkdir temp: %w", err)
	}

	clone := command(ctx, token, "git", "clone", "--quiet", remote, dir)
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

// cloneURL turns git@host:path and ssh://git@host/path into https://host/path when a
// token is set. Git sends that token only to HTTPS. Without a token the URL is unchanged.
func cloneURL(raw, token string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("repository url is empty")
	}
	if token == "" {
		return raw, nil
	}
	if host, path, ok := strings.Cut(strings.TrimPrefix(raw, "git@"), ":"); ok && strings.HasPrefix(raw, "git@") && host != "" && path != "" {
		return "https://" + host + "/" + strings.TrimPrefix(path, "/"), nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("invalid repository url")
	}
	switch parsed.Scheme {
	case "https", "http", "ssh":
		parsed.Scheme = "https"
		parsed.User = nil
		return parsed.String(), nil
	default:
		return "", fmt.Errorf("unsupported repository url")
	}
}

func command(ctx context.Context, token string, args ...string) *exec.Cmd {
	if token != "" {
		args = withCredentials(args)
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = gitEnv(token)
	return cmd
}

func withCredentials(args []string) []string {
	if len(args) == 0 || args[0] != "git" {
		return args
	}
	// Drop inherited helpers. The child reads the password from GIT_TOKEN, so the
	// token value stays out of the process arguments and the remote URL.
	out := []string{
		"git",
		"-c", "credential.helper=",
		"-c", `credential.helper=!f() { printf 'username=x-access-token\npassword=%s\n' "$GIT_TOKEN"; }; f`,
	}
	return append(out, args[1:]...)
}

func Remove(dir string) {
	if dir == "" {
		return
	}
	_ = os.RemoveAll(dir)
}

func gitEnv(token string) []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, item := range os.Environ() {
		if strings.HasPrefix(item, "GIT_TOKEN=") || strings.HasPrefix(item, "GIT_ASKPASS=") {
			continue
		}
		env = append(env, item)
	}
	env = append(env, "GIT_TERMINAL_PROMPT=0")
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
