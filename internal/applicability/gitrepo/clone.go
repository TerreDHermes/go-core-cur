package gitrepo

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

// Clone creates a temp directory and clones only branch into it.
// A separate checkout is not used: the remote sends that one branch, at depth 1.
// The caller must Remove the returned directory.
// token is the HTTPS password from GIT_TOKEN. An SSH URL is cloned over HTTPS so the
// same token is used. An empty token clones the URL as given, without credentials.
func Clone(ctx context.Context, rawURL, branch, token string) (string, error) {
	remote, user, err := cloneURL(rawURL, token)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(branch) == "" {
		return "", fmt.Errorf("git clone: branch is empty")
	}
	dir, err := cloneInto(ctx, token, user, remote, branch, true)
	if err != nil && certificateError(err) {
		// git.slo and other internal forges are signed by a private CA.
		// The handshake fails before the token is sent. Repeat without that check.
		dir, err = cloneInto(ctx, token, user, remote, branch, false)
	}
	return dir, err
}

func cloneInto(ctx context.Context, token, user, remote, branch string, verify bool) (string, error) {
	dir, err := os.MkdirTemp("", "cve-analysis-*")
	if err != nil {
		return "", fmt.Errorf("mkdir temp: %w", err)
	}
	clone := command(ctx, token, cloneArgs(user, verify, remote, branch, dir)...)
	if out, err := clone.CombinedOutput(); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("git clone: %w: %s", err, trim(out, token))
	}
	return dir, nil
}

func certificateError(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "ssl certificate problem") ||
		strings.Contains(text, "unable to get local issuer certificate") ||
		strings.Contains(text, "server certificate verification failed")
}

// cloneCommandArgs fetches one branch tip. Full history and the other branches stay on the remote.
// The "--" keeps a branch name that contains a slash from being read as the repository path.
func cloneCommandArgs(remote, branch, dir string) []string {
	return []string{"git", "clone", "--quiet", "--single-branch", "--depth", "1", "--branch", branch, "--", remote, dir}
}

// cloneURL returns the https address git should fetch and the username for the token.
// The address is always https://host/group/project.git: the .git suffix is what
// GitHub, GitLab and Gitea serve as the repository, and a page without it is not.
// user is oauth2 everywhere except GitHub, where the username is x-access-token.
// An empty token leaves an ssh address unchanged and returns an empty user.
func cloneURL(raw, token string) (remote, user string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("repository url is empty")
	}
	// Without a token an ssh address is used as written: there is no https password to send.
	if token == "" && (strings.HasPrefix(raw, "git@") || strings.HasPrefix(strings.ToLower(raw), "ssh:")) {
		return raw, "", nil
	}
	parsed, err := parseRemote(raw)
	if err != nil {
		return "", "", err
	}
	if token != "" || parsed.Scheme == "ssh" {
		parsed.Scheme = "https"
		user = credentialUser(parsed.Host)
	}
	parsed.User = nil
	parsed.Path = repositoryPath(parsed.Path)
	if parsed.Path == "" || parsed.Path == ".git" || parsed.Path == "/.git" {
		return "", "", fmt.Errorf("invalid repository url")
	}
	if token == "" {
		user = ""
	}
	return parsed.String(), user, nil
}

func parseRemote(raw string) (*url.URL, error) {
	if host, path, ok := strings.Cut(strings.TrimPrefix(raw, "git@"), ":"); ok && strings.HasPrefix(raw, "git@") && host != "" && path != "" {
		return &url.URL{Scheme: "https", Host: host, Path: "/" + strings.TrimPrefix(path, "/")}, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("invalid repository url")
	}
	switch parsed.Scheme {
	case "https", "http", "ssh":
		return parsed, nil
	default:
		return nil, fmt.Errorf("unsupported repository url")
	}
}

// repositoryPath is the project path with a single .git suffix and no trailing slash.
func repositoryPath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.TrimRight(path, "/")
	if path == "" {
		return ""
	}
	if !strings.HasSuffix(strings.ToLower(path), ".git") {
		path += ".git"
	}
	return path
}

// credentialUser is the username git sends with the token.
// GitHub expects x-access-token. GitLab, Gitea and the rest take oauth2;
// the token itself is always the password.
func credentialUser(host string) string {
	host = strings.ToLower(host)
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	if host == "github.com" || strings.HasSuffix(host, ".github.com") {
		return "x-access-token"
	}
	return "oauth2"
}

func cloneArgs(user string, verify bool, remote, branch, dir string) []string {
	args := cloneCommandArgs(remote, branch, dir)
	if user != "" {
		args = withCredentials(args, user)
	}
	if verify {
		return args
	}
	return append([]string{args[0], "-c", "http.sslVerify=false"}, args[1:]...)
}

func command(ctx context.Context, token string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = gitEnv(token)
	return cmd
}

func withCredentials(args []string, user string) []string {
	if len(args) == 0 || args[0] != "git" {
		return args
	}
	if user == "" {
		user = "oauth2"
	}
	// Drop inherited helpers. The child reads the password from GIT_TOKEN, so the
	// token value stays out of the process arguments and the remote URL.
	// %s is the shell printf verb; the username is the only part we fill in here.
	helper := fmt.Sprintf(
		`credential.helper=!f() { printf 'username=%s\npassword=%%s\n' "$GIT_TOKEN"; }; f`,
		user,
	)
	out := []string{
		"git",
		"-c", "credential.helper=",
		"-c", helper,
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
