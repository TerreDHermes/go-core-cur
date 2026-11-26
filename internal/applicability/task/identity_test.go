package task

import "testing"

func TestCVEIdentityPrefersCVEThenGOThenGHSA(t *testing.T) {
	primary, aliases := CVEIdentity("GHSA-q7gw-24fr-5p69", CVEPatch{
		CVE:     "GO-2026-6974",
		Aliases: []string{"CVE-2026-128085", "GHSA-q7gw-24fr-5p69"},
	})
	if primary != "CVE-2026-128085" {
		t.Fatal(primary)
	}
	if !sameIDs(aliases, "go-2026-6974", "ghsa-q7gw-24fr-5p69", "cve-2026-128085") {
		t.Fatal(aliases)
	}

	primary, _ = CVEIdentity("ghsa-aaaa-bbbb-cccc", CVEPatch{
		CVE:     "GO-2026-1",
		Aliases: []string{"GHSA-aaaa-bbbb-cccc"},
	})
	if primary != "GO-2026-1" {
		t.Fatal(primary)
	}

	primary, _ = CVEIdentity("cve-2024-1", CVEPatch{Aliases: []string{"GHSA-zzzz-yyyy-xxxx"}})
	if primary != "cve-2024-1" {
		t.Fatal(primary)
	}

	primary, aliases = CVEIdentity("  PYSEC-1 ", CVEPatch{})
	if primary != "PYSEC-1" || len(aliases) != 1 || aliases[0] != "pysec-1" {
		t.Fatalf("%s %v", primary, aliases)
	}
}

func sameIDs(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]int{}
	for _, id := range got {
		seen[id]++
	}
	for _, id := range want {
		seen[id]--
		if seen[id] < 0 {
			return false
		}
	}
	return true
}
