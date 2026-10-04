package gitrepo

import (
	"strings"
	"testing"
)

func TestCloneArgsKeepTokenOutOfArgv(t *testing.T) {
	args := cloneArgs("https://github.com/acme/private", "/tmp/repo", "secret-token")
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "secret-token") {
		t.Fatalf("token leaked into args: %s", joined)
	}
	if !strings.Contains(joined, "credential.helper=") || !strings.Contains(joined, "$GIT_TOKEN") {
		t.Fatalf("args: %s", joined)
	}
}

func TestGitEnvCarriesToken(t *testing.T) {
	env := gitEnv("secret-token")
	var found bool
	for _, item := range env {
		if item == "GIT_TOKEN=secret-token" {
			found = true
		}
		if strings.HasPrefix(item, "GIT_ASKPASS=") {
			t.Fatalf("askpass set together with a token: %s", item)
		}
	}
	if !found {
		t.Fatal("GIT_TOKEN missing")
	}
}

func TestTrimRedactsToken(t *testing.T) {
	got := trim([]byte("auth failed for secret-token"), "secret-token")
	if strings.Contains(got, "secret-token") || !strings.Contains(got, "[redacted]") {
		t.Fatal(got)
	}
}
