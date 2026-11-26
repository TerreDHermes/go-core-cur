package gitrepo

import "testing"

func TestCanonicalRepoURL(t *testing.T) {
	const want = "https://git.slo/dapp/dapp-grafana.git"
	for _, raw := range []string{
		"git@git.slo:dapp/dapp-grafana.git",
		"ssh://git@git.slo/dapp/dapp-grafana.git",
		"https://git.slo/dapp/dapp-grafana",
		"https://git.slo/dapp/dapp-grafana/",
		"https://git.slo/dapp/dapp-grafana.git",
		"https://oauth2@git.slo/dapp/dapp-grafana.git",
		"http://Git.Slo/dapp/dapp-grafana",
		"  https://git.slo/dapp/dapp-grafana.git  ",
	} {
		if got := CanonicalRepoURL(raw); got != want {
			t.Errorf("%q -> %q", raw, got)
		}
	}
	if got := CanonicalRepoURL("https://git.slo/dapp/Dapp-Grafana"); got != "https://git.slo/dapp/Dapp-Grafana.git" {
		t.Fatal(got)
	}
	if got := CanonicalRepoURL("https://git.slo:8443/dapp/dapp-grafana"); got != "https://git.slo:8443/dapp/dapp-grafana.git" {
		t.Fatal(got)
	}
	if got := CanonicalRepoURL("u"); got != "u" {
		t.Fatal(got)
	}
	if CanonicalRepoURL("  ") != "" {
		t.Fatal("blank")
	}
}
