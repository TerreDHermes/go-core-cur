package gitrepo

import (
	"strings"
	"testing"
)

func TestCloneArgsKeepTokenOutOfArgv(t *testing.T) {
	remote, err := cloneURL("git@github.com:TerreDHermes/go-core-cur.git", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	args := withCredentials([]string{"git", "clone", "--quiet", remote, "/tmp/repo"})
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "secret-token") {
		t.Fatalf("token leaked into args: %s", joined)
	}
	if !strings.Contains(joined, "https://github.com/TerreDHermes/go-core-cur.git") {
		t.Fatalf("args: %s", joined)
	}
	if !strings.Contains(joined, "credential.helper=") || !strings.Contains(joined, "$GIT_TOKEN") {
		t.Fatalf("args: %s", joined)
	}
}

func TestCloneURLUsesTokenForHTTPSAndSSH(t *testing.T) {
	https, err := cloneURL("https://github.com/TerreDHermes/go-core-cur.git", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	ssh, err := cloneURL("git@github.com:TerreDHermes/go-core-cur.git", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	sshURL, err := cloneURL("ssh://git@github.com/TerreDHermes/go-core-cur.git", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://github.com/TerreDHermes/go-core-cur.git"
	if https != want || ssh != want || sshURL != want {
		t.Fatalf("https %s ssh %s sshURL %s", https, ssh, sshURL)
	}
	plain, err := cloneURL("git@github.com:TerreDHermes/go-core-cur.git", "")
	if err != nil {
		t.Fatal(err)
	}
	if plain != "git@github.com:TerreDHermes/go-core-cur.git" {
		t.Fatal(plain)
	}
	withUser, err := cloneURL("https://someone@github.com/TerreDHermes/go-core-cur.git", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if withUser != want {
		t.Fatal(withUser)
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
