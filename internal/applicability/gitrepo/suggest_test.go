package gitrepo

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSuggestProjectsFiltersTheGroup(t *testing.T) {
	var pages int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "secret" {
			t.Errorf("token header %q", r.Header.Get("PRIVATE-TOKEN"))
		}
		if !strings.Contains(r.URL.Path, "/api/v4/groups/dapp/projects") {
			t.Fatalf("path %s", r.URL.Path)
		}
		if r.URL.Query().Get("include_subgroups") != "true" {
			t.Fatal(r.URL.RawQuery)
		}
		pages++
		w.Header().Set("Content-Type", "application/json")
		if pages == 1 {
			w.Header().Set("X-Next-Page", "2")
			_, _ = w.Write([]byte(`[{"id":1,"name":"cilium","path_with_namespace":"dapp/dapp-cilium","default_branch":"main"}]`))
			return
		}
		_, _ = w.Write([]byte(`[{"id":2,"name":"grafana","path_with_namespace":"dapp/obs/dapp-grafana","default_branch":"release/k8sc-6.0.0"},{"id":3,"name":"other","path_with_namespace":"elsewhere/nope","default_branch":"main"}]`))
	}))
	defer srv.Close()

	cat := catalogFor(t, srv, "secret")
	cat.pageSize = 1
	got, err := cat.Projects(context.Background(), "graf")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Path != "dapp/obs/dapp-grafana" || got[0].URL != srv.URL+"/dapp/obs/dapp-grafana.git" || got[0].DefaultBranch != "release/k8sc-6.0.0" {
		t.Fatalf("%+v", got)
	}
	if pages != 2 {
		t.Fatal(pages)
	}

	again, err := cat.Projects(context.Background(), "graf")
	if err != nil || len(again) != 1 || pages != 2 {
		t.Fatalf("cache %+v pages %d err %v", again, pages, err)
	}

	foreign, err := cat.Projects(context.Background(), "https://github.com/org/grafana")
	if err != nil || foreign != nil {
		t.Fatalf("%+v %v", foreign, err)
	}
}

func TestSuggestRetriesUnauthorizedWithBearer(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			if r.Header.Get("PRIVATE-TOKEN") == "" {
				t.Fatal("expected private token")
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("auth %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`[{"id":7,"name":"grafana","path_with_namespace":"dapp/dapp-grafana","default_branch":"main"}]`))
	}))
	defer srv.Close()

	got, err := catalogFor(t, srv, "secret").Projects(context.Background(), "")
	if err != nil || len(got) != 1 || got[0].Path != "dapp/dapp-grafana" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestSuggestBranchesOfAKnownProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/projects/4/repository/branches"):
			if r.URL.Query().Get("search") == "rel" {
				_, _ = w.Write([]byte(`[{"name":"release/k8sc-6.0.0","default":false}]`))
				return
			}
			_, _ = w.Write([]byte(`[{"name":"release/k8sc-6.0.0","default":false},{"name":"main","default":true}]`))
		case strings.Contains(r.URL.Path, "/groups/dapp/projects"):
			_, _ = w.Write([]byte(`[{"id":4,"name":"grafana","path_with_namespace":"dapp/dapp-grafana","default_branch":"main"}]`))
		default:
			t.Fatalf("path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	cat := catalogFor(t, srv, "secret")
	raw := srv.URL + "/dapp/dapp-grafana.git"
	got, err := cat.Branches(context.Background(), raw, "rel")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "release/k8sc-6.0.0" || got[0].Default {
		t.Fatalf("%+v", got)
	}
	all, err := cat.Branches(context.Background(), raw, "")
	if err != nil || len(all) != 2 || all[0].Name != "main" || !all[0].Default || all[1].Name != "release/k8sc-6.0.0" {
		t.Fatalf("%+v %v", all, err)
	}
	host, path, ok := repoIdentity("git@git.slo:dapp/dapp-grafana.git")
	if !ok || host != "git.slo" || path != "dapp/dapp-grafana" {
		t.Fatal(host, path, ok)
	}
}

func TestSuggestIgnoresOtherForgesAndMissingToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("forge was called")
	}))
	defer srv.Close()

	cat := catalogFor(t, srv, "secret")
	branches, err := cat.Branches(context.Background(), "https://github.com/org/repo.git", "main")
	if err != nil || branches != nil {
		t.Fatalf("%+v %v", branches, err)
	}
	empty := catalogFor(t, srv, "")
	projects, err := empty.Projects(context.Background(), "graf")
	if err != nil || projects != nil {
		t.Fatalf("%+v %v", projects, err)
	}
	off := NewCatalog("secret", "")
	projects, err = off.Projects(context.Background(), "graf")
	if err != nil || projects != nil {
		t.Fatalf("%+v %v", projects, err)
	}
}

func TestSearchNeedle(t *testing.T) {
	cases := []struct {
		query  string
		needle string
		skip   bool
	}{
		{query: "graf", needle: "graf"},
		{query: "dapp/dapp-graf", needle: "dapp/dapp-graf"},
		{query: "https://git.slo/dapp/dapp-grafana.git", needle: "dapp/dapp-grafana"},
		{query: "git@git.slo:dapp/dapp-grafana.git", needle: "dapp/dapp-grafana"},
		{query: "https://github.com/org/repo", skip: true},
		{query: "github.com/org/repo", skip: true},
		{query: "", needle: ""},
	}
	for _, tc := range cases {
		needle, skip := searchNeedle(tc.query, "git.slo")
		if needle != tc.needle || skip != tc.skip {
			t.Fatalf("%q got %q skip %v", tc.query, needle, skip)
		}
	}
}

func TestSuggestRetriesUntrustedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":2,"name":"grafana","path_with_namespace":"dapp/dapp-grafana","default_branch":"main"}]`))
	}))
	defer srv.Close()

	got, err := catalogFor(t, srv, "secret").Projects(context.Background(), "graf")
	if err != nil || len(got) != 1 || got[0].Path != "dapp/dapp-grafana" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestTLSCertError(t *testing.T) {
	err := &url.Error{Op: "Get", Err: x509.UnknownAuthorityError{Cert: &x509.Certificate{}}}
	if !tlsCertError(err) {
		t.Fatal(err)
	}
}

func catalogFor(t *testing.T, srv *httptest.Server, token string) *Catalog {
	t.Helper()
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return NewCatalog(token, parsed.Scheme+"://"+parsed.Host+"/dapp")
}
