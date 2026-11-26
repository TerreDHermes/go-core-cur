package gitrepo

import "strings"

// CanonicalRepoURL is the working https address of a repository.
// SSH, a missing .git suffix, a trailing slash and a login in the URL
// all become https://host/group/project.git. The host is compared without
// case. The project path keeps its case. An address that is not a remote
// is returned trimmed, so a lookup still matches what was stored.
func CanonicalRepoURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := parseRemote(raw)
	if err != nil {
		return raw
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return raw
	}
	if port := parsed.Port(); port != "" {
		host += ":" + port
	}
	path := repositoryPath(parsed.Path)
	if strings.HasSuffix(strings.ToLower(path), ".git") {
		path = path[:len(path)-4] + ".git"
	}
	if path == "" || path == ".git" || path == "/.git" {
		return raw
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return "https://" + host + path
}
