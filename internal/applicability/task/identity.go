package task

import "strings"

// CVEIdentity chooses the id to store and every id that should find this task.
// primary prefers a CVE id, then a GO- id, then a GHSA id. The card's own cve
// field wins inside one kind, then the id the run was started with, then the
// aliases in order. aliases includes primary and is folded for an exact match.
// Before the card arrives, pass a zero CVEPatch: the set is only the typed id.
func CVEIdentity(requested string, patch CVEPatch) (primary string, aliases []string) {
	var items []cveName
	seen := map[string]bool{}
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		key := strings.ToLower(raw)
		if seen[key] {
			return
		}
		seen[key] = true
		items = append(items, cveName{raw: raw, key: key, kind: cveKind(key)})
	}
	add(patch.CVE)
	add(requested)
	for _, alias := range patch.Aliases {
		add(alias)
	}
	for _, kind := range []string{"cve", "go", "ghsa"} {
		if raw, ok := firstKind(items, kind); ok {
			primary = raw
			break
		}
	}
	if primary == "" {
		if raw := strings.TrimSpace(patch.CVE); raw != "" {
			primary = raw
		} else {
			primary = strings.TrimSpace(requested)
		}
	}
	if primary != "" {
		add(primary)
	}
	for _, item := range items {
		aliases = append(aliases, item.key)
	}
	return primary, aliases
}

type cveName struct {
	raw  string
	key  string
	kind string
}

func cveKind(key string) string {
	switch {
	case strings.HasPrefix(key, "cve-"):
		return "cve"
	case strings.HasPrefix(key, "go-"):
		return "go"
	case strings.HasPrefix(key, "ghsa-"):
		return "ghsa"
	default:
		return ""
	}
}

func firstKind(items []cveName, kind string) (string, bool) {
	for _, item := range items {
		if item.kind == kind {
			return item.raw, true
		}
	}
	return "", false
}
