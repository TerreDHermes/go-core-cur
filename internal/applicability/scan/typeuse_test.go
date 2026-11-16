package scan

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"cve-patch-viewer/internal/applicability/task"
)

func TestTypesInPatchReadsDeclarationAndHeader(t *testing.T) {
	diff := `@@ -1,3 +1,4 @@ type Config struct
 type Config struct {
 	Host string
+	Name string
 }
`
	got := typesInPatch(diff)
	if len(got) != 1 || got[0] != "Config" {
		t.Fatal(got)
	}
	if len(typesInPatch("@@\n func Host() string {\n")) != 0 {
		t.Fatal("function is not a type")
	}
}

func TestEnclosingTypeFromChangedField(t *testing.T) {
	src := "package config\n\ntype Config struct {\n\tHost string\n\tPort int\n}\n\ntype Other struct {\n\tName string\n}\n"
	diff := "@@\n \tHost string\n+\tName string\n \tPort int\n"
	got := enclosingTypes(src, diff)
	if len(got) != 1 || got[0] != "Config" {
		t.Fatal(got)
	}
}

func TestUnusedStructIsNotApplicable(t *testing.T) {
	called := false
	restore := stubModuleDeadcode(t, func(context.Context, string, bool) moduleDeadcode {
		called = true
		return moduleDeadcode{Status: "ok"}
	})
	defer restore()

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.22.0\n")
	mustWrite(t, filepath.Join(root, "pkg", "config", "config.go"), "package config\n\ntype Config struct {\n\tHost string\n}\n")
	report := analyzeReach(context.Background(), root, []task.PatchFile{{
		Filename: "pkg/config/config.go",
		Patch:    "@@ type Config struct\n type Config struct {\n+\tName string\n }\n",
	}}, []task.PatchFileMatch{{
		Filename: "pkg/config/config.go",
		Found:    true,
		Path:     "./pkg/config/config.go",
	}})
	if called {
		t.Fatal("deadcode ran for an unused type")
	}
	if report.Reachable == nil || *report.Reachable {
		t.Fatal(report.Reachable, report.Detail)
	}
	if !strings.Contains(report.Detail, "Config") || !strings.Contains(report.Detail, "не используется") {
		t.Fatal(report.Detail)
	}
}

func TestStructMethodGoesToDeadcode(t *testing.T) {
	var symbol string
	restore := stubModuleDeadcode(t, func(context.Context, string, bool) moduleDeadcode {
		return moduleDeadcode{Status: "ok", Dead: map[string]struct{}{
			"example.com/app/pkg/config.Config.Host": {},
		}}
	})
	defer restore()

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.22.0\n")
	mustWrite(t, filepath.Join(root, "pkg", "config", "config.go"), "package config\n\ntype Config struct {\n\tHost string\n}\n\nfunc (c *Config) Host() string {\n\treturn c.Host\n}\n")
	report := analyzeReach(context.Background(), root, []task.PatchFile{{
		Filename: "pkg/config/config.go",
		Patch:    "@@ type Config struct\n type Config struct {\n+\tName string\n }\n",
	}}, []task.PatchFileMatch{{
		Filename: "pkg/config/config.go",
		Found:    true,
		Path:     "./pkg/config/config.go",
	}})
	if report.Reachable == nil || *report.Reachable {
		t.Fatal(report.Reachable, report.Detail)
	}
	if len(report.Functions) != 1 || report.Functions[0].Symbol != "example.com/app/pkg/config.Config.Host" {
		t.Fatalf("%+v", report.Functions)
	}
	symbol = report.Functions[0].Symbol
	if symbol == "" {
		t.Fatal("empty symbol")
	}
}

func TestExportedTypeUseInAnotherPackage(t *testing.T) {
	restore := stubModuleDeadcode(t, func(context.Context, string, bool) moduleDeadcode {
		return moduleDeadcode{Status: "ok", Dead: map[string]struct{}{}}
	})
	defer restore()

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.22.0\n")
	mustWrite(t, filepath.Join(root, "pkg", "config", "config.go"), "package config\n\ntype Config struct {\n\tHost string\n}\n")
	mustWrite(t, filepath.Join(root, "cmd", "main.go"), "package main\n\nimport \"example.com/app/pkg/config\"\n\nfunc main() {}\n\nfunc use(c config.Config) {}\n")
	report := analyzeReach(context.Background(), root, []task.PatchFile{{
		Filename: "pkg/config/config.go",
		Patch:    "@@\n type Config struct {\n+\tName string\n }\n",
	}}, []task.PatchFileMatch{{
		Filename: "pkg/config/config.go",
		Found:    true,
		Path:     "./pkg/config/config.go",
	}})
	if report.Reachable == nil || !*report.Reachable {
		t.Fatal(report.Reachable, report.Detail)
	}
	if len(report.Functions) != 1 || report.Functions[0].Symbol != "example.com/app/cmd.use" {
		t.Fatalf("%+v", report.Functions)
	}
}

func TestUnexportedTypeOutsidePackageDoesNotCount(t *testing.T) {
	called := false
	restore := stubModuleDeadcode(t, func(context.Context, string, bool) moduleDeadcode {
		called = true
		return moduleDeadcode{Status: "ok"}
	})
	defer restore()

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.22.0\n")
	mustWrite(t, filepath.Join(root, "pkg", "config", "config.go"), "package config\n\ntype config struct {\n\tHost string\n}\n")
	mustWrite(t, filepath.Join(root, "cmd", "main.go"), "package main\n\nfunc use(c config) {}\n")
	report := analyzeReach(context.Background(), root, []task.PatchFile{{
		Filename: "pkg/config/config.go",
		Patch:    "@@ type config struct\n type config struct {\n+\tName string\n }\n",
	}}, []task.PatchFileMatch{{
		Filename: "pkg/config/config.go",
		Found:    true,
		Path:     "./pkg/config/config.go",
	}})
	if called {
		t.Fatal("deadcode ran")
	}
	if report.Reachable == nil || *report.Reachable {
		t.Fatal(report.Reachable, report.Detail)
	}
}

func TestOuterStructMethodIsChecked(t *testing.T) {
	restore := stubModuleDeadcode(t, func(context.Context, string, bool) moduleDeadcode {
		return moduleDeadcode{Status: "ok", Dead: map[string]struct{}{
			"example.com/app/pkg/config.Server.Run": {},
		}}
	})
	defer restore()

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.22.0\n")
	mustWrite(t, filepath.Join(root, "pkg", "config", "config.go"), "package config\n\ntype Config struct {\n\tHost string\n}\n\ntype Server struct {\n\tcfg Config\n}\n\nfunc (s *Server) Run() {}\n")
	report := analyzeReach(context.Background(), root, []task.PatchFile{{
		Filename: "pkg/config/config.go",
		Patch:    "@@ type Config struct\n type Config struct {\n+\tName string\n }\n",
	}}, []task.PatchFileMatch{{
		Filename: "pkg/config/config.go",
		Found:    true,
		Path:     "./pkg/config/config.go",
	}})
	if len(report.Functions) != 1 || report.Functions[0].Symbol != "example.com/app/pkg/config.Server.Run" {
		t.Fatalf("%+v detail %s", report.Functions, report.Detail)
	}
	if report.Reachable == nil || *report.Reachable {
		t.Fatal(report.Reachable, report.Detail)
	}
}

func TestFunctionInPatchStaysOnTheOldPath(t *testing.T) {
	restore := stubModuleDeadcode(t, func(context.Context, string, bool) moduleDeadcode {
		return moduleDeadcode{Status: "ok", Dead: map[string]struct{}{
			"example.com/app/pkg/config.Parse": {},
		}}
	})
	defer restore()

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.22.0\n")
	mustWrite(t, filepath.Join(root, "pkg", "config", "config.go"), "package config\n\ntype Config struct {\n\tHost string\n}\n\nfunc Parse(c *Config) {}\n\nfunc (c *Config) Host() string { return c.Host }\n")
	report := analyzeReach(context.Background(), root, []task.PatchFile{{
		Filename: "pkg/config/config.go",
		Patch:    "@@ func Parse\n func Parse(c *Config) {\n+\treturn\n }\n",
	}}, []task.PatchFileMatch{{
		Filename: "pkg/config/config.go",
		Found:    true,
		Path:     "./pkg/config/config.go",
	}})
	if len(report.Functions) != 1 || report.Functions[0].Symbol != "example.com/app/pkg/config.Parse" {
		t.Fatalf("%+v", report.Functions)
	}
}

func TestUnreadableTypeStaysUnknown(t *testing.T) {
	called := false
	restore := stubModuleDeadcode(t, func(context.Context, string, bool) moduleDeadcode {
		called = true
		return moduleDeadcode{Status: "ok"}
	})
	defer restore()

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/app\n\ngo 1.22.0\n")
	mustWrite(t, filepath.Join(root, "pkg", "config", "config.go"), "package config\n\ntype Config struct {\n\tHost string\n}\n")
	report := analyzeReach(context.Background(), root, []task.PatchFile{{
		Filename: "pkg/config/config.go",
		Patch:    "@@\n+\t// only a comment\n",
	}}, []task.PatchFileMatch{{
		Filename: "pkg/config/config.go",
		Found:    true,
		Path:     "./pkg/config/config.go",
	}})
	if called {
		t.Fatal("deadcode ran")
	}
	if report.Reachable != nil {
		t.Fatal(report.Reachable, report.Detail)
	}
	if !strings.Contains(report.Detail, "ни функцию, ни тип") {
		t.Fatal(report.Detail)
	}
}
