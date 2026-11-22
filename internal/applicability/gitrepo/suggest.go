package gitrepo

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	suggestLimit     = 20
	projectPageSize  = 100
	maxProjectPages  = 30
	projectCacheTTL  = 5 * time.Minute
	suggestHTTPLimit = 20 * time.Second
)

// ProjectSuggestion is one repository from the configured group.
// URL is the https address the clone step already accepts.
type ProjectSuggestion struct {
	Path          string `json:"path"`
	URL           string `json:"url"`
	DefaultBranch string `json:"default_branch,omitempty"`
}

// BranchSuggestion is one branch of a project from that group.
type BranchSuggestion struct {
	Name    string `json:"name"`
	Default bool   `json:"default"`
}

// Catalog lists projects and branches of one GitLab group.
// A missing token or an empty root returns no suggestions and does not call the forge.
type Catalog struct {
	scheme   string
	host     string
	name     string
	group    string
	token    string
	ttl      time.Duration
	pageSize int

	mu       sync.Mutex
	cached   []projectEntry
	loaded   time.Time
	insecure bool
	bearer   bool
	client   *http.Client
}

type projectEntry struct {
	ID            int
	Path          string
	Name          string
	DefaultBranch string
	URL           string
}

// NewCatalog reads a group URL such as https://git.slo/dapp.
// A blank or unusable URL disables suggestions.
func NewCatalog(token, root string) *Catalog {
	c := &Catalog{token: strings.TrimSpace(token), ttl: projectCacheTTL}
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(root), "/"))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return c
	}
	group := strings.Trim(parsed.Path, "/")
	if group == "" {
		return c
	}
	c.scheme = parsed.Scheme
	c.host = parsed.Host
	c.name = parsed.Hostname()
	c.group = group
	return c
}

func (c *Catalog) enabled() bool {
	return c != nil && c.token != "" && c.scheme != "" && c.host != "" && c.group != ""
}

// Projects returns up to 20 repositories whose path or name contains query.
// An empty query returns the first 20 in path order. A query that names another
// forge returns nothing.
func (c *Catalog) Projects(ctx context.Context, query string) ([]ProjectSuggestion, error) {
	if !c.enabled() {
		return nil, nil
	}
	needle, skip := searchNeedle(query, c.name)
	if skip {
		return nil, nil
	}
	all, err := c.projects(ctx)
	if err != nil {
		return nil, err
	}
	matched := make([]projectEntry, 0, suggestLimit)
	for _, item := range all {
		if needle == "" || projectMatches(item, needle) {
			matched = append(matched, item)
		}
	}
	sort.SliceStable(matched, func(i, j int) bool {
		ri, rj := projectRank(matched[i], needle), projectRank(matched[j], needle)
		if ri != rj {
			return ri < rj
		}
		return matched[i].Path < matched[j].Path
	})
	if len(matched) > suggestLimit {
		matched = matched[:suggestLimit]
	}
	out := make([]ProjectSuggestion, 0, len(matched))
	for _, item := range matched {
		out = append(out, ProjectSuggestion{Path: item.Path, URL: item.URL, DefaultBranch: item.DefaultBranch})
	}
	return out, nil
}

// Branches returns branches of a repository that belongs to the configured group.
// componentURL may be https or ssh. Anything outside the group is an empty list.
func (c *Catalog) Branches(ctx context.Context, componentURL, query string) ([]BranchSuggestion, error) {
	if !c.enabled() {
		return nil, nil
	}
	host, path, ok := repoIdentity(componentURL)
	if !ok || !sameHost(host, c.name) || !underGroup(path, c.group) {
		return nil, nil
	}
	item, err := c.projectByPath(ctx, path)
	if err != nil || item.ID == 0 {
		return nil, err
	}
	got, err := c.fetchBranches(ctx, item, strings.TrimSpace(query))
	if err != nil {
		return nil, err
	}
	return got, nil
}

func (c *Catalog) projectByPath(ctx context.Context, path string) (projectEntry, error) {
	all, err := c.projects(ctx)
	if err != nil {
		return projectEntry{}, err
	}
	if item, ok := findProject(all, path); ok {
		return item, nil
	}
	c.mu.Lock()
	c.loaded = time.Time{}
	c.mu.Unlock()
	all, err = c.projects(ctx)
	if err != nil {
		return projectEntry{}, err
	}
	item, _ := findProject(all, path)
	return item, nil
}

func findProject(all []projectEntry, path string) (projectEntry, bool) {
	for _, item := range all {
		if strings.EqualFold(item.Path, path) {
			return item, true
		}
	}
	return projectEntry{}, false
}

func (c *Catalog) projects(ctx context.Context) ([]projectEntry, error) {
	c.mu.Lock()
	if c.cached != nil && time.Since(c.loaded) < c.ttl {
		out := c.cached
		c.mu.Unlock()
		return out, nil
	}
	c.mu.Unlock()

	fresh, err := c.fetchProjects(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		if c.cached != nil {
			return c.cached, nil
		}
		return nil, err
	}
	c.cached = fresh
	c.loaded = time.Now()
	return fresh, nil
}

func (c *Catalog) fetchProjects(ctx context.Context) ([]projectEntry, error) {
	size := c.pageSize
	if size <= 0 {
		size = projectPageSize
	}
	var all []projectEntry
	for page := 1; page <= maxProjectPages; page++ {
		u := fmt.Sprintf("%s://%s/api/v4/groups/%s/projects?include_subgroups=true&simple=true&archived=false&with_shared=false&order_by=name&sort=asc&per_page=%d&page=%d",
			c.scheme, c.host, url.PathEscape(c.group), size, page)
		body, header, status, err := c.get(ctx, u)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("gitlab projects: http %d", status)
		}
		var rows []struct {
			ID                int    `json:"id"`
			Name              string `json:"name"`
			PathWithNamespace string `json:"path_with_namespace"`
			DefaultBranch     string `json:"default_branch"`
		}
		if err := json.Unmarshal(body, &rows); err != nil {
			return nil, fmt.Errorf("gitlab projects: %w", err)
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			path := strings.Trim(row.PathWithNamespace, "/")
			if row.ID == 0 || path == "" || !underGroup(path, c.group) {
				continue
			}
			all = append(all, projectEntry{
				ID:            row.ID,
				Path:          path,
				Name:          row.Name,
				DefaultBranch: row.DefaultBranch,
				URL:           fmt.Sprintf("%s://%s/%s.git", c.scheme, c.host, path),
			})
		}
		if header.Get("X-Next-Page") == "" || len(rows) < size {
			break
		}
	}
	return all, nil
}

func (c *Catalog) fetchBranches(ctx context.Context, item projectEntry, query string) ([]BranchSuggestion, error) {
	u := fmt.Sprintf("%s://%s/api/v4/projects/%d/repository/branches?per_page=%d", c.scheme, c.host, item.ID, suggestLimit)
	if query != "" {
		u += "&search=" + url.QueryEscape(query)
	}
	body, _, status, err := c.get(ctx, u)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("gitlab branches: http %d", status)
	}
	var rows []struct {
		Name    string `json:"name"`
		Default bool   `json:"default"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("gitlab branches: %w", err)
	}
	out := make([]BranchSuggestion, 0, len(rows)+1)
	seen := map[string]bool{}
	needle := strings.ToLower(query)
	if item.DefaultBranch != "" && (needle == "" || strings.Contains(strings.ToLower(item.DefaultBranch), needle)) {
		out = append(out, BranchSuggestion{Name: item.DefaultBranch, Default: true})
		seen[item.DefaultBranch] = true
	}
	for _, row := range rows {
		name := strings.TrimSpace(row.Name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, BranchSuggestion{Name: name, Default: row.Default || name == item.DefaultBranch})
		if len(out) >= suggestLimit {
			break
		}
	}
	return out, nil
}

func (c *Catalog) get(ctx context.Context, rawURL string) ([]byte, http.Header, int, error) {
	body, header, status, err := c.do(ctx, rawURL)
	if err != nil {
		return nil, nil, 0, redact(err, c.token)
	}
	if status == http.StatusUnauthorized {
		c.mu.Lock()
		switched := !c.bearer
		c.bearer = true
		c.mu.Unlock()
		if switched {
			body, header, status, err = c.do(ctx, rawURL)
			if err != nil {
				return nil, nil, 0, redact(err, c.token)
			}
		}
	}
	return body, header, status, nil
}

func (c *Catalog) do(ctx context.Context, rawURL string) ([]byte, http.Header, int, error) {
	resp, err := c.roundTrip(ctx, rawURL)
	if err != nil && tlsCertError(err) {
		c.mu.Lock()
		switched := !c.insecure
		c.insecure = true
		c.client = nil
		c.mu.Unlock()
		if switched {
			resp, err = c.roundTrip(ctx, rawURL)
		}
	}
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, 8<<20)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, nil, resp.StatusCode, err
	}
	return body, resp.Header.Clone(), resp.StatusCode, nil
}

func (c *Catalog) roundTrip(ctx context.Context, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	bearer := c.bearer
	client := c.httpClient()
	c.mu.Unlock()
	if bearer {
		req.Header.Set("Authorization", "Bearer "+c.token)
	} else {
		req.Header.Set("PRIVATE-TOKEN", c.token)
	}
	return client.Do(req)
}

func (c *Catalog) httpClient() *http.Client {
	if c.client != nil {
		return c.client
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if c.insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	c.client = &http.Client{
		Timeout:   suggestHTTPLimit,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || !sameHost(req.URL.Hostname(), c.name) {
				return errors.New("gitlab redirect refused")
			}
			return nil
		},
	}
	return c.client
}

func tlsCertError(err error) bool {
	if err == nil {
		return false
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return true
	}
	var hostname x509.HostnameError
	if errors.As(err, &hostname) {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "certificate") || strings.Contains(text, "x509")
}

func redact(err error, token string) error {
	if err == nil || token == "" || !strings.Contains(err.Error(), token) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), token, "[redacted]"))
}

func searchNeedle(query, host string) (needle string, skip bool) {
	q := strings.TrimSpace(strings.ToLower(query))
	q = strings.TrimSuffix(q, ".git")
	q = strings.TrimRight(q, "/")
	if q == "" {
		return "", false
	}
	if strings.HasPrefix(q, "git@") {
		rest := strings.TrimPrefix(q, "git@")
		gotHost, path, ok := strings.Cut(rest, ":")
		if !ok || !hostAllowed(gotHost, host) {
			return "", true
		}
		return strings.Trim(strings.TrimSuffix(path, ".git"), "/"), false
	}
	if strings.Contains(q, "://") {
		rest := q
		if i := strings.Index(rest, "://"); i >= 0 {
			rest = rest[i+3:]
		}
		gotHost, path, _ := strings.Cut(rest, "/")
		if gotHost != "" && !hostAllowed(gotHost, host) {
			return "", true
		}
		return strings.Trim(strings.TrimSuffix(path, ".git"), "/"), false
	}
	if strings.HasPrefix(q, strings.ToLower(host)+"/") {
		q = strings.TrimPrefix(q, strings.ToLower(host)+"/")
	}
	first, _, _ := strings.Cut(q, "/")
	if strings.Contains(first, ".") && !hostAllowed(first, host) {
		return "", true
	}
	return strings.Trim(q, "/"), false
}

func hostAllowed(got, want string) bool {
	got = strings.ToLower(strings.TrimSpace(got))
	want = strings.ToLower(strings.TrimSpace(want))
	if i := strings.LastIndex(got, ":"); i >= 0 {
		got = got[:i]
	}
	if i := strings.LastIndex(want, ":"); i >= 0 {
		want = want[:i]
	}
	return got == "" || got == want || strings.HasPrefix(want, got)
}

func sameHost(got, want string) bool {
	return strings.EqualFold(strings.TrimSpace(got), strings.TrimSpace(want))
}

func underGroup(path, group string) bool {
	path = strings.Trim(path, "/")
	group = strings.Trim(group, "/")
	return path == group || strings.HasPrefix(strings.ToLower(path), strings.ToLower(group)+"/")
}

func projectMatches(item projectEntry, needle string) bool {
	needle = strings.ToLower(needle)
	return strings.Contains(strings.ToLower(item.Path), needle) || strings.Contains(strings.ToLower(item.Name), needle)
}

func projectRank(item projectEntry, needle string) int {
	if needle == "" {
		return 3
	}
	needle = strings.ToLower(needle)
	name := strings.ToLower(item.Name)
	path := strings.ToLower(item.Path)
	last := path
	if i := strings.LastIndex(path, "/"); i >= 0 {
		last = path[i+1:]
	}
	switch {
	case last == needle || name == needle:
		return 0
	case strings.HasPrefix(last, needle) || strings.HasPrefix(name, needle):
		return 1
	case strings.HasPrefix(path, needle):
		return 2
	default:
		return 3
	}
}

func repoIdentity(raw string) (host, path string, ok bool) {
	parsed, err := parseRemote(strings.TrimSpace(raw))
	if err != nil {
		return "", "", false
	}
	p := strings.TrimPrefix(repositoryPath(parsed.Path), "/")
	if strings.HasSuffix(strings.ToLower(p), ".git") {
		p = p[:len(p)-4]
	}
	p = strings.Trim(p, "/")
	if parsed.Hostname() == "" || p == "" {
		return "", "", false
	}
	return parsed.Hostname(), p, true
}
