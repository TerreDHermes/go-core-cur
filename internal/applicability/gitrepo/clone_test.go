package gitrepo

import (
	"strings"
	"testing"
)

func TestCloneArgsKeepTokenOutOfArgv(t *testing.T) {
	remote, user, err := cloneURL("git@github.com:TerreDHermes/go-core-cur.git", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if user != "x-access-token" {
		t.Fatal(user)
	}
	args := withCredentials(cloneCommandArgs(remote, "main", "/tmp/repo"), user)
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "secret-token") {
		t.Fatalf("token leaked into args: %s", joined)
	}
	if !strings.Contains(joined, "https://github.com/TerreDHermes/go-core-cur.git") {
		t.Fatalf("args: %s", joined)
	}
	if !strings.Contains(joined, "credential.helper=") || !strings.Contains(joined, "$GIT_TOKEN") || !strings.Contains(joined, "username=x-access-token") {
		t.Fatalf("args: %s", joined)
	}
	if !strings.Contains(joined, "--single-branch") || !strings.Contains(joined, "--depth 1") || !strings.Contains(joined, "--branch main") {
		t.Fatalf("args: %s", joined)
	}
	if strings.Contains(joined, "checkout") {
		t.Fatalf("args: %s", joined)
	}
}

func TestCloneURLUsesTokenForHTTPSAndSSH(t *testing.T) {
	https, user, err := cloneURL("https://github.com/TerreDHermes/go-core-cur.git", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	ssh, sshUser, err := cloneURL("git@github.com:TerreDHermes/go-core-cur.git", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	sshURL, _, err := cloneURL("ssh://git@github.com/TerreDHermes/go-core-cur.git", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://github.com/TerreDHermes/go-core-cur.git"
	if https != want || ssh != want || sshURL != want || user != "x-access-token" || sshUser != "x-access-token" {
		t.Fatalf("https %s ssh %s sshURL %s user %s", https, ssh, sshURL, user)
	}
	plain, plainUser, err := cloneURL("git@github.com:TerreDHermes/go-core-cur.git", "")
	if err != nil {
		t.Fatal(err)
	}
	if plain != "git@github.com:TerreDHermes/go-core-cur.git" || plainUser != "" {
		t.Fatal(plain, plainUser)
	}
	withUser, _, err := cloneURL("https://someone@github.com/TerreDHermes/go-core-cur.git", "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	if withUser != want {
		t.Fatal(withUser)
	}
}

func TestCloneURLNormalizesGitLabPathAndUser(t *testing.T) {
	cases := []string{
		"https://git.slo/dapp/dapp-cilium",
		"https://git.slo/dapp/dapp-cilium/",
		"https://git.slo/dapp/dapp-cilium.git",
		"git@git.slo:dapp/dapp-cilium.git",
		"ssh://git@git.slo/dapp/dapp-cilium",
	}
	for _, raw := range cases {
		remote, user, err := cloneURL(raw, "secret-token")
		if err != nil {
			t.Fatal(raw, err)
		}
		if remote != "https://git.slo/dapp/dapp-cilium.git" || user != "oauth2" {
			t.Fatalf("%s -> %s user %s", raw, remote, user)
		}
		if strings.Contains(remote, "secret-token") {
			t.Fatal(remote)
		}
	}
	args := withCredentials(cloneCommandArgs("https://git.slo/dapp/dapp-cilium.git", "release/k8sc-6.0.0", "/tmp/repo"), "oauth2")
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "username=oauth2") || !strings.Contains(joined, "--branch release/k8sc-6.0.0") {
		t.Fatal(joined)
	}
	if !strings.Contains(joined, "-- https://git.slo/dapp/dapp-cilium.git") {
		t.Fatal(joined)
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
