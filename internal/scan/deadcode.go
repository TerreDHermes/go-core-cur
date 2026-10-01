package scan

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// whyLiveFunc asks deadcode whether symbol is reachable from main.
// Tests replace it. status is live, dead, missing, no-main, or failed.
var whyLiveFunc = runWhyLive

func runWhyLive(ctx context.Context, moduleDir string, useVendor bool, symbol string) (string, string, error) {
	bin, err := exec.LookPath("deadcode")
	if err != nil {
		return "failed", "", fmt.Errorf("бинарник deadcode не найден в PATH")
	}
	cmd := exec.CommandContext(ctx, bin, "-whylive="+symbol, "./...")
	cmd.Dir = moduleDir
	cmd.Env = os.Environ()
	if useVendor {
		cmd.Env = withVendorMod(cmd.Env)
	}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err = cmd.Run()
	out := buf.String()
	if len(out) > 4000 {
		out = out[:4000]
	}
	return classifyWhyLive(err, out), out, nil
}

func classifyWhyLive(err error, out string) string {
	switch {
	case strings.Contains(out, "is dead code"):
		return "dead"
	case strings.Contains(out, "not found in program"):
		return "missing"
	case strings.Contains(out, "no main packages"):
		return "no-main"
	case err != nil || strings.TrimSpace(out) == "":
		return "failed"
	default:
		return "live"
	}
}

func withVendorMod(env []string) []string {
	for i, entry := range env {
		if !strings.HasPrefix(entry, "GOFLAGS=") {
			continue
		}
		if strings.Contains(entry, "-mod=") {
			return env
		}
		env[i] = entry + " -mod=vendor"
		return env
	}
	return append(env, "GOFLAGS=-mod=vendor")
}
