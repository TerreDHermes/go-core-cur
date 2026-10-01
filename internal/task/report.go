package task

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Report is the per-go.mod document. Fields stay separate for later use.
// Markdown renders the same data as one string for the download endpoint.
const (
	StageNotGo         = "not_go"
	StagePackageAbsent = "package_absent"
	StageNoVendor      = "no_vendor"
	StageNoPatch       = "no_patch"
	StagePatchFiles    = "patch_files"
)

type Report struct {
	GoModPath       string           `json:"go_mod_path"`
	Stage           string           `json:"stage"`
	FromRoot        bool             `json:"from_root,omitempty"`
	HasVendor       bool             `json:"has_vendor"`
	VendorPath      string           `json:"vendor_path,omitempty"`
	MatchingLines   []string         `json:"matching_lines"`
	Version         string           `json:"version,omitempty"`
	PreVerdict      string           `json:"pre_verdict,omitempty"`
	PatchFiles      []PatchFileMatch `json:"patch_files,omitempty"`
	FoundPatchFiles []string         `json:"found_patch_files,omitempty"`
	Grep            *GrepReport      `json:"grep,omitempty"`
	Patch           CVEPatch         `json:"patch"`
}

// GrepReport is the no-patch search: phrases chosen from the description
// and a bounded list of matches. The bound keeps the later model call small.
type GrepReport struct {
	Patterns          []string      `json:"patterns"`
	Hits              []GrepHit     `json:"hits"`
	Excerpts          []GrepExcerpt `json:"excerpts"`
	Truncated         bool          `json:"truncated"`
	ExcerptsTruncated bool          `json:"excerpts_truncated"`
}

// GrepHit is one grep -rwn style match.
type GrepHit struct {
	Pattern string `json:"pattern"`
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Text    string `json:"text"`
}

// GrepExcerpt is a bounded slice of the file around a grep hit.
// For Go it prefers the enclosing function. Later hits in the same slice do not copy it again.
type GrepExcerpt struct {
	Path string `json:"path"`
	From int    `json:"from"`
	To   int    `json:"to"`
	Text string `json:"text"`
}

// PatchFileMatch is one file from the CVE patch.
// Found is true when that file exists in this module's tree, false when it does not.
// Every patch file is listed. All false means none of the patch files are in the project.
type PatchFileMatch struct {
	Filename string `json:"filename"`
	Found    bool   `json:"found"`
	Path     string `json:"path,omitempty"`
}

// CVEPatch is the body of GET /cve/patch/{cveID}.
type CVEPatch struct {
	CVE           string            `json:"cve"`
	Description   string            `json:"description"`
	DescriptionRU string            `json:"description_ru"`
	Aliases       []string          `json:"aliases"`
	References    []CVEReference    `json:"references"`
	FixURL        string            `json:"fix_url"`
	ProjectInfo   ProjectInfo       `json:"project_info"`
	Message       string            `json:"message,omitempty"`
	Files         []PatchFile       `json:"files,omitempty"`
	FixedVersions []string          `json:"fixed_versions"`
	CVSSScores    map[string]string `json:"cvss_scores"`
	NISTDates     NISTDates         `json:"nist_dates"`
}

type CVEReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type ProjectInfo struct {
	Vendor           string   `json:"vendor"`
	Product          string   `json:"product"`
	CollectionURL    string   `json:"collection_url"`
	PackageName      string   `json:"package_name"`
	Project          string   `json:"project"`
	ProjectFromPatch string   `json:"project_from_patch,omitempty"`
	FixedVersions    []string `json:"fixed_versions"`
}

type PatchFile struct {
	Filename string `json:"filename"`
	Patch    string `json:"patch"`
}

type NISTDates struct {
	PublishedDate    string `json:"published_date"`
	LastModifiedDate string `json:"last_modified_date"`
}

// ConnectionResetPhrase is the message fragment that means the patch service
// answered before it could download the diff. The caller retries while this is set.
const ConnectionResetPhrase = "read: connection reset by peer"

func (p CVEPatch) NeedsPatchRetry() bool {
	return strings.Contains(p.Message, ConnectionResetPhrase)
}

// Markdown assembles every saved field into one document.
func (r Report) Markdown() string {
	var b strings.Builder
	title := r.GoModPath
	if r.FromRoot {
		title = "root"
	}
	fmt.Fprintf(&b, "# %s\n\n", title)
	if r.Stage != "" {
		fmt.Fprintf(&b, "Stage: `%s`\n\n", r.Stage)
	}
	if r.FromRoot {
		b.WriteString("Search: repository root\n\n")
	} else if r.HasVendor {
		fmt.Fprintf(&b, "Vendor: yes (`%s`)\n\n", r.VendorPath)
	} else {
		b.WriteString("Vendor: no\n\n")
	}
	if r.Version != "" {
		fmt.Fprintf(&b, "Version: `%s`\n\n", r.Version)
	}
	if r.PreVerdict != "" {
		fmt.Fprintf(&b, "Pre-verdict: %s\n\n", r.PreVerdict)
	}
	if r.Grep != nil {
		b.WriteString("Grep patterns:\n\n")
		if len(r.Grep.Patterns) == 0 {
			b.WriteString("(none)\n")
		}
		for _, pattern := range r.Grep.Patterns {
			fmt.Fprintf(&b, "- `%s`\n", pattern)
		}
		b.WriteString("\nGrep hits:\n\n")
		if len(r.Grep.Hits) == 0 {
			b.WriteString("(none)\n")
		}
		for _, hit := range r.Grep.Hits {
			fmt.Fprintf(&b, "- `%s` %s:%d: %s\n", hit.Pattern, hit.Path, hit.Line, hit.Text)
		}
		if r.Grep.Truncated {
			b.WriteString("\nGrep truncated: yes\n")
		}
		b.WriteString("\nGrep excerpts:\n\n")
		if len(r.Grep.Excerpts) == 0 {
			b.WriteString("(none)\n\n")
		}
		for _, excerpt := range r.Grep.Excerpts {
			fmt.Fprintf(&b, "`%s` lines %d-%d\n\n```\n%s", excerpt.Path, excerpt.From, excerpt.To, excerpt.Text)
			if !strings.HasSuffix(excerpt.Text, "\n") {
				b.WriteByte('\n')
			}
			b.WriteString("```\n\n")
		}
		if r.Grep.ExcerptsTruncated {
			b.WriteString("Grep excerpts truncated: yes\n\n")
		}
	}
	if len(r.PatchFiles) > 0 {
		b.WriteString("Patch files:\n\n")
		for _, file := range r.PatchFiles {
			if file.Found {
				fmt.Fprintf(&b, "- `%s`: true (`%s`)\n", file.Filename, file.Path)
				continue
			}
			fmt.Fprintf(&b, "- `%s`: false\n", file.Filename)
		}
		b.WriteByte('\n')
	}
	b.WriteString("Matching lines:\n\n")
	if len(r.MatchingLines) == 0 {
		b.WriteString("(none)\n")
	}
	for _, line := range r.MatchingLines {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteString("\n## CVE patch\n\n")
	raw, err := json.MarshalIndent(r.Patch, "", "  ")
	if err != nil {
		fmt.Fprintf(&b, "failed to render patch: %s\n", err)
		return b.String()
	}
	b.Write(raw)
	b.WriteByte('\n')
	return b.String()
}
