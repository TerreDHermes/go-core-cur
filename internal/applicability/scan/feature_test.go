package scan

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"cve-patch-viewer/internal/applicability/task"
)

func TestParseFeatureCondition(t *testing.T) {
	imp, call, ok := parseFeatureCondition("import: google.golang.org/grpc/authz\ncall: authz.New\n")
	if !ok || imp != "google.golang.org/grpc/authz" || call != "authz.New" {
		t.Fatalf("%s %s %v", imp, call, ok)
	}
	imp, call, ok = parseFeatureCondition("import: `google.golang.org/grpc`\ncall: пусто\n")
	if !ok || imp != "google.golang.org/grpc" || call != "" {
		t.Fatalf("%s %s %v", imp, call, ok)
	}
	if _, _, ok := parseFeatureCondition("Method\n:path\nFullMethod\n"); ok {
		t.Fatal("generic words must not become a condition")
	}
}

func TestFeatureCallIgnoresVendorAndAlias(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "vendor", "google.golang.org", "grpc", "authz", "authz.go"), "package authz\n\nfunc New() {}\n")
	mustWrite(t, filepath.Join(root, "pkg", "use.go"), `package use

import az "google.golang.org/grpc/authz"

func Enable() { az.NewStatic() }
`)
	mustWrite(t, filepath.Join(root, "pkg", "use_test.go"), `package use

import "google.golang.org/grpc/authz"

func TestNew(t *testing.T) { authz.New() }
`)
	found, err := featureCallUsed(root, "google.golang.org/grpc/authz", "authz.New")
	if err != nil || !found {
		t.Fatalf("found %v err %v", found, err)
	}

	onlyVendor := t.TempDir()
	mustWrite(t, filepath.Join(onlyVendor, "vendor", "google.golang.org", "grpc", "authz", "authz.go"), "package authz\n\nfunc New() {}\n")
	mustWrite(t, filepath.Join(onlyVendor, "main.go"), "package main\n\nfunc main() {}\n")
	found, err = featureCallUsed(onlyVendor, "google.golang.org/grpc/authz", "authz.New")
	if err != nil || found {
		t.Fatalf("found %v err %v", found, err)
	}
}

func TestNoPatchFeatureDecidesWithoutGrep(t *testing.T) {
	cases := []struct {
		name   string
		main   string
		answer string
		want   string
		used   *bool
		detail string
	}{
		{
			name:   "feature not imported",
			main:   "package main\n\nimport \"google.golang.org/grpc\"\n\nfunc main() { grpc.Server() }\n",
			answer: "import: google.golang.org/grpc/authz\ncall: authz.New\n",
			want:   task.NotApplicable,
			used:   boolPtr(false),
			detail: "не входит в сборку main",
		},
		{
			name:   "imported but not called",
			main:   "package main\n\nimport (\n\t\"google.golang.org/grpc\"\n\t_ \"google.golang.org/grpc/authz\"\n)\n\nfunc main() { grpc.Server() }\n",
			answer: "import: google.golang.org/grpc/authz\ncall: authz.New\n",
			want:   task.NotApplicable,
			used:   boolPtr(false),
			detail: "вызов authz.New в коде приложения не найден",
		},
		{
			name:   "called",
			main:   "package main\n\nimport (\n\t\"google.golang.org/grpc\"\n\t\"google.golang.org/grpc/authz\"\n)\n\nfunc main() {\n\tgrpc.Server()\n\tauthz.NewStatic()\n}\n",
			answer: "import: google.golang.org/grpc/authz\ncall: authz.New\n",
			want:   task.Applicable,
			used:   boolPtr(true),
			detail: "вызывает authz.New",
		},
		{
			name:   "default path",
			main:   "package main\n\nimport \"google.golang.org/grpc\"\n\nfunc main() { grpc.Server() }\n",
			answer: "import: google.golang.org/grpc\ncall:\n",
			want:   task.Applicable,
			used:   boolPtr(true),
			detail: "на обычном пути этого пакета",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeVendoredGrpc(t, root, tc.main)
			got, err := Scan(context.Background(), Input{
				RepoPath:     root,
				ComponentURL: "https://github.com/grafana/loki",
				CVEID:        "CVE-2026-33186",
				PackageName:  "google.golang.org/grpc",
			}, describedPatch{}, scriptedAI{answer: tc.answer})
			if err != nil {
				t.Fatal(err)
			}
			if got[0].ReportMD.Grep != nil {
				t.Fatal("description grep must not decide a vendored module")
			}
			feature := got[0].ReportMD.Feature
			if feature == nil || feature.Used == nil || *feature.Used != *tc.used {
				t.Fatalf("%+v", feature)
			}
			if got[0].Applicability != tc.want || !strings.Contains(feature.Detail, tc.detail) {
				t.Fatalf("%s %s", got[0].Applicability, feature.Detail)
			}
		})
	}
}

func TestNoPatchWithoutMainStaysUncertain(t *testing.T) {
	root := t.TempDir()
	writeVendoredGrpc(t, root, "")
	got, err := Scan(context.Background(), Input{
		RepoPath:    root,
		CVEID:       "CVE-2026-33186",
		PackageName: "google.golang.org/grpc",
	}, describedPatch{}, scriptedAI{answer: "import: google.golang.org/grpc\ncall:\n"})
	if err != nil {
		t.Fatal(err)
	}
	feature := got[0].ReportMD.Feature
	if feature == nil || feature.Used != nil || got[0].Applicability != task.Uncertain {
		t.Fatalf("%+v %s", feature, got[0].Applicability)
	}
	if !strings.Contains(feature.Detail, "нет package main") {
		t.Fatal(feature.Detail)
	}
}

type scriptedAI struct {
	answer string
}

func (s scriptedAI) Explain(_ context.Context, prompt string) (string, error) {
	if strings.Contains(prompt, "подробный журнал") {
		return "narrative-text", nil
	}
	if strings.Contains(prompt, "условие, без которого") {
		return s.answer, nil
	}
	return "model-verdict", nil
}

func writeVendoredGrpc(t *testing.T, root, main string) {
	t.Helper()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.22.0\n\nrequire google.golang.org/grpc v1.59.0\n")
	mustWrite(t, filepath.Join(root, "vendor", "modules.txt"), "# google.golang.org/grpc v1.59.0\n## explicit; go 1.19\ngoogle.golang.org/grpc\ngoogle.golang.org/grpc/authz\n")
	mustWrite(t, filepath.Join(root, "vendor", "google.golang.org", "grpc", "grpc.go"), "package grpc\n\nfunc Server() {}\n")
	mustWrite(t, filepath.Join(root, "vendor", "google.golang.org", "grpc", "authz", "authz.go"), "package authz\n\nfunc New() {}\n\nfunc NewStatic() {}\n")
	if main != "" {
		mustWrite(t, filepath.Join(root, "cmd", "main.go"), main)
	}
}
