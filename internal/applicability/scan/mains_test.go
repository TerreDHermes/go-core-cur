package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cve-patch-viewer/internal/applicability/task"
)

func TestParseGoListAndDropBrokenMain(t *testing.T) {
	raw := `{"ImportPath":"example.com/app","Dir":"/mod","Name":"app","Imports":["example.com/app/pkg"]}
{"ImportPath":"example.com/app/pkg","Dir":"/mod/pkg","Name":"pkg"}
{"ImportPath":"example.com/app/cmd/good","Dir":"/mod/cmd/good","Name":"main","Imports":["example.com/app/pkg"]}
{"ImportPath":"example.com/app/cmd/bad","Dir":"/mod/cmd/bad","Name":"main","Imports":["example.com/app/broken"]}
{"ImportPath":"example.com/app/broken","Dir":"/mod/broken","Name":"broken"}
`
	pkgs, err := parseGoListJSON(raw)
	if err != nil || len(pkgs) != 5 {
		t.Fatal(err, len(pkgs))
	}
	mains := mainPackages(pkgs)
	if len(mains) != 2 || mains[0].ImportPath != "example.com/app/cmd/bad" {
		t.Fatal(mains)
	}
	errOut := "/mod/broken/target.go:38:17: undefined: Metrics\n/mod/broken/target.go:48:9: undefined: Metrics\ndeadcode: packages contain errors"
	files := filesFromCompileError(errOut)
	if len(files) != 1 || files[0] != "/mod/broken/target.go" {
		t.Fatal(files)
	}
	kept, dropped, broken := dropBrokenMains("/mod", pkgs, mains, errOut)
	if len(broken) != 1 || len(kept) != 1 || kept[0].ImportPath != "example.com/app/cmd/good" {
		t.Fatalf("kept %+v dropped %v", kept, dropped)
	}
	if strings.Join(dropped, ",") != "./cmd/bad" {
		t.Fatal(dropped)
	}
	if strings.Join(mainPatterns("/mod", mains), ",") != ".,./cmd/bad,./cmd/good" && strings.Join(mainPatterns("/mod", mains), ",") != "./cmd/bad,./cmd/good" {
		t.Fatal(mainPatterns("/mod", mains))
	}
}

func TestClassifySkipsCodeOutsideBuiltMains(t *testing.T) {
	res := moduleDeadcode{
		Status: "ok",
		Dead:   map[string]struct{}{"example.com/app/pkg.Dead": {}},
		Loaded: map[string]struct{}{"example.com/app/pkg": {}, "example.com/app": {}},
	}
	if status, _ := classifyModuleSymbol(res, "example.com/app/pkg.Dead"); status != "dead" {
		t.Fatal(status)
	}
	if status, _ := classifyModuleSymbol(res, "example.com/app/pkg.Live"); status != "live" {
		t.Fatal(status)
	}
	if status, _ := classifyModuleSymbol(res, "example.com/app/broken.Bad"); status != "missing" {
		t.Fatal(status)
	}
	open := moduleDeadcode{Status: "ok", Dead: map[string]struct{}{}}
	if status, _ := classifyModuleSymbol(open, "example.com/app/broken.Bad"); status != "live" {
		t.Fatal(status)
	}
}

func TestBrokenVulnFileStaysUnknown(t *testing.T) {
	restore := stubModuleDeadcode(t, func(context.Context, string, bool) moduleDeadcode {
		return moduleDeadcode{
			Status:      "ok",
			Loaded:      map[string]struct{}{"example.com/app/other": {}},
			BrokenFiles: []string{"/repo/pkg/vuln.go"},
			Skipped:     []string{"./cmd/bad"},
		}
	})
	defer restore()

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n")
	mustWrite(t, filepath.Join(root, "pkg", "vuln.go"), "package pkg\n\nfunc Vuln() {}\n")
	report := analyzeReach(context.Background(), root, []task.PatchFile{{
		Filename: "pkg/vuln.go",
		Patch:    "@@\n func Vuln() {}\n",
	}}, []task.PatchFileMatch{{
		Filename: "pkg/vuln.go",
		Found:    true,
		Path:     "pkg/vuln.go",
	}})
	if report.Reachable != nil {
		t.Fatal(report.Reachable, report.Detail)
	}
	if !strings.Contains(report.Detail, "не компилируется") || !strings.Contains(report.Detail, "Из сборки убраны main") {
		t.Fatal(report.Detail)
	}
}

func TestUncalledByBuiltMainsIsNotApplicable(t *testing.T) {
	restore := stubModuleDeadcode(t, func(context.Context, string, bool) moduleDeadcode {
		return moduleDeadcode{
			Status:  "ok",
			Loaded:  map[string]struct{}{"example.com/app/cmd/good": {}},
			Skipped: []string{"./cmd/bad"},
		}
	})
	defer restore()

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n")
	mustWrite(t, filepath.Join(root, "pkg", "vuln.go"), "package pkg\n\nfunc Vuln() {}\n")
	report := analyzeReach(context.Background(), root, []task.PatchFile{{
		Filename: "pkg/vuln.go",
		Patch:    "@@\n func Vuln() {}\n",
	}}, []task.PatchFileMatch{{
		Filename: "pkg/vuln.go",
		Found:    true,
		Path:     "pkg/vuln.go",
	}})
	if report.Reachable == nil || *report.Reachable {
		t.Fatal(report.Reachable, report.Detail)
	}
	if !strings.Contains(report.Detail, "недостижим") || !strings.Contains(report.Detail, "./cmd/bad") {
		t.Fatal(report.Detail)
	}
}

func TestVendorPackageDropsOnlyItsMain(t *testing.T) {
	raw := `{"ImportPath":"example.com/app/cmd/good","Dir":"/mod/cmd/good","Name":"main","Imports":["example.com/app/pkg"]}
{"ImportPath":"example.com/app/pkg","Dir":"/mod/pkg","Name":"pkg"}
{"ImportPath":"example.com/app/cmd/bad","Dir":"/mod/cmd/bad","Name":"main","Imports":["github.com/NVIDIA/go-nvml/pkg/nvml"]}
`
	pkgs, err := parseGoListJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	file := "/mod/vendor/github.com/NVIDIA/go-nvml/pkg/nvml/zz_generated.api.go"
	got, ok := vendorImportPath("/mod", file)
	if !ok || got != "github.com/NVIDIA/go-nvml/pkg/nvml" {
		t.Fatal(got, ok)
	}
	errOut := file + ":783:24: undefined: Return\ndeadcode: packages contain errors"
	kept, dropped, _ := dropBrokenMains("/mod", pkgs, mainPackages(pkgs), errOut)
	if len(kept) != 1 || kept[0].ImportPath != "example.com/app/cmd/good" || strings.Join(dropped, ",") != "./cmd/bad" {
		t.Fatalf("kept %+v dropped %v", kept, dropped)
	}
}

func TestTransitiveVendorPackageNeedsDeps(t *testing.T) {
	shallow := []listedPackage{
		{ImportPath: "example.com/app/cmd/good", Dir: "/mod/cmd/good", Name: "main", Imports: []string{"example.com/app/pkg"}},
		{ImportPath: "example.com/app/pkg", Dir: "/mod/pkg", Name: "pkg"},
		{ImportPath: "example.com/app/cmd/bad", Dir: "/mod/cmd/bad", Name: "main", Imports: []string{"k8s.io/gpu"}},
	}
	file := "/mod/vendor/github.com/NVIDIA/go-nvml/pkg/nvml/zz_generated.api.go"
	errOut := file + ":783:24: undefined: Return"
	kept, dropped, _ := dropBrokenMains("/mod", shallow, mainPackages(shallow), errOut)
	if len(dropped) != 0 || len(kept) != 2 {
		t.Fatalf("shallow graph must keep both mains, dropped %v", dropped)
	}
	deps := append(shallow, listedPackage{
		ImportPath: "k8s.io/gpu", Dir: "/mod/vendor/k8s.io/gpu", Name: "gpu",
		Imports: []string{"github.com/NVIDIA/go-nvml/pkg/nvml"},
	}, listedPackage{
		ImportPath: "github.com/NVIDIA/go-nvml/pkg/nvml",
		Dir:        "/mod/vendor/github.com/NVIDIA/go-nvml/pkg/nvml",
		Name:       "nvml",
	})
	kept, dropped, _ = dropBrokenMains("/mod", deps, mainPackages(shallow), errOut)
	if len(kept) != 1 || kept[0].ImportPath != "example.com/app/cmd/good" || strings.Join(dropped, ",") != "./cmd/bad" {
		t.Fatalf("kept %+v dropped %v", kept, dropped)
	}
}

func TestLoadDepsGraphSeesVendorPackage(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.22.0\n\nrequire github.com/NVIDIA/go-nvml v0.0.0\n")
	mustWrite(t, filepath.Join(root, "vendor", "modules.txt"), "# github.com/NVIDIA/go-nvml v0.0.0\n## explicit\ngithub.com/NVIDIA/go-nvml/pkg/nvml\n")
	mustWrite(t, filepath.Join(root, "vendor", "github.com", "NVIDIA", "go-nvml", "pkg", "nvml", "api.go"), "package nvml\n\nfunc Bad() { var x Return }\n")
	mustWrite(t, filepath.Join(root, "pkg", "ok.go"), "package pkg\n\nfunc Live() {}\n")
	mustWrite(t, filepath.Join(root, "cmd", "good", "main.go"), "package main\n\nimport \"example.com/app/pkg\"\n\nfunc main() { pkg.Live() }\n")
	mustWrite(t, filepath.Join(root, "cmd", "bad", "main.go"), "package main\n\nimport \"github.com/NVIDIA/go-nvml/pkg/nvml\"\n\nfunc main() { nvml.Bad() }\n")

	env := withVendorMod(os.Environ())
	graph, err := loadModuleGraph(context.Background(), root, env)
	if err != nil {
		t.Fatal(err)
	}
	mains := mainPackages(graph)
	deps, err := loadDepsGraph(context.Background(), root, env, mainPatterns(root, mains))
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "vendor", "github.com", "NVIDIA", "go-nvml", "pkg", "nvml", "api.go")
	errOut := file + ":3:20: undefined: Return\ndeadcode: packages contain errors"
	kept, dropped, _ := dropBrokenMains(root, deps, mains, errOut)
	if len(kept) != 1 || len(dropped) != 1 || dropped[0] != "./cmd/bad" {
		t.Fatalf("kept %+v dropped %v", kept, dropped)
	}
}

func TestLoadModuleGraphListsMains(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.22.0\n")
	mustWrite(t, filepath.Join(root, "pkg", "ok.go"), "package pkg\n\nfunc Live() {}\n")
	mustWrite(t, filepath.Join(root, "broken", "broken.go"), "package broken\n\nfunc Bad() { var x Undefined }\n")
	mustWrite(t, filepath.Join(root, "cmd", "good", "main.go"), "package main\n\nimport \"example.com/app/pkg\"\n\nfunc main() { pkg.Live() }\n")
	mustWrite(t, filepath.Join(root, "cmd", "bad", "main.go"), "package main\n\nimport \"example.com/app/broken\"\n\nfunc main() { broken.Bad() }\n")

	pkgs, err := loadModuleGraph(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	mains := mainPackages(pkgs)
	errOut := filepath.Join(root, "broken", "broken.go") + ":3:20: undefined: Undefined\ndeadcode: packages contain errors"
	kept, dropped, _ := dropBrokenMains(root, pkgs, mains, errOut)
	if len(kept) != 1 || len(dropped) != 1 || dropped[0] != "./cmd/bad" {
		t.Fatalf("kept %+v dropped %v", kept, dropped)
	}
	loaded, err := dependencySet(context.Background(), root, nil, mainPatterns(root, kept))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded["example.com/app/pkg"]; !ok {
		t.Fatal(loaded)
	}
	if _, ok := loaded["example.com/app/broken"]; ok {
		t.Fatal("good main must not load the broken package")
	}
}
