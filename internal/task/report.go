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
	GoModPath       string   `json:"go_mod_path"`
	Stage           string   `json:"stage"`
	HasVendor       bool     `json:"has_vendor"`
	VendorPath      string   `json:"vendor_path,omitempty"`
	MatchingLines   []string `json:"matching_lines"`
	FoundPatchFiles []string `json:"found_patch_files,omitempty"`
	Patch           CVEPatch `json:"patch"`
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
	fmt.Fprintf(&b, "# %s\n\n", r.GoModPath)
	if r.Stage != "" {
		fmt.Fprintf(&b, "Stage: `%s`\n\n", r.Stage)
	}
	if r.HasVendor {
		fmt.Fprintf(&b, "Vendor: yes (`%s`)\n\n", r.VendorPath)
	} else {
		b.WriteString("Vendor: no\n\n")
	}
	if len(r.FoundPatchFiles) > 0 {
		b.WriteString("Patch files found:\n\n")
		for _, path := range r.FoundPatchFiles {
			b.WriteString(path)
			b.WriteByte('\n')
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
