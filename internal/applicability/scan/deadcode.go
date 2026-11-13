package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// deadcodeLimit is the budget of one deadcode run. The task deadline is separate
// and still ends the whole analysis. Past this limit the run is stopped and
// reachability stays unknown, so the model can still write a verdict.
// The clock starts after a slot is acquired, so time spent waiting does not count.
const deadcodeLimit = 4 * time.Minute

// deadcodeSlots is how many heavy Go program loads may run in this process at once.
// deadcode and, for the standard library, go list -deps each take one slot.
// Each one loads a whole module, so five of them exhaust the machine
// even when the CPU still has idle cores.
const deadcodeSlots = 2

// deadcodeGate hands out deadcodeSlots. A send takes a slot, a receive returns it.
var deadcodeGate = make(chan struct{}, deadcodeSlots)

// moduleDeadcode is one deadcode invocation for every symbol in a module.
// Status is ok, no-main, or failed. Dead holds symbols that deadcode reported
// unreachable, in the same form as ReachFunc.Symbol.
type moduleDeadcode struct {
	Status string
	Dead   map[string]struct{}
	Output string
}

// runModuleDeadcode executes deadcode once per module. Tests replace it.
var runModuleDeadcode = executeModuleDeadcode

func executeModuleDeadcode(ctx context.Context, moduleDir string, useVendor bool) moduleDeadcode {
	bin, err := exec.LookPath("deadcode")
	if err != nil {
		return moduleDeadcode{Status: "failed", Output: "бинарник deadcode не найден в PATH"}
	}
	if err := acquireDeadcode(ctx); err != nil {
		return moduleDeadcode{Status: "failed", Output: err.Error()}
	}
	defer releaseDeadcode()

	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, deadcodeLimit)
	defer cancel()

	env := deadcodeEnv(ctx, useVendor)
	stdout, stderr, err := runGrouped(ctx, moduleDir, env, bin, deadcodeArgs()...)
	if err == nil {
		dead, perr := parseDeadcode(stdout)
		if perr != nil {
			return moduleDeadcode{Status: "failed", Output: "deadcode вернул неразборный список функций"}
		}
		return moduleDeadcode{Status: "ok", Dead: dead}
	}
	out := strings.TrimSpace(stderr)
	if out == "" {
		out = err.Error()
	}
	if strings.Contains(out, "no main packages") {
		return moduleDeadcode{Status: "no-main", Output: trimRunOutput(out)}
	}
	if ctx.Err() != nil && time.Since(started) >= deadcodeLimit-2*time.Second {
		return moduleDeadcode{Status: "failed", Output: deadcodeTimeoutOutput()}
	}
	if ctx.Err() != nil && strings.TrimSpace(stderr) == "" {
		out = ctx.Err().Error()
	}
	return moduleDeadcode{Status: "failed", Output: trimRunOutput(out)}
}

// acquireDeadcode waits until fewer than deadcodeSlots runs are active.
// The stage stays on the queue until the slot is taken, and a cancelled task
// leaves the queue without starting a process.
func acquireDeadcode(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	prev := swapStage(ctx, "ожидание deadcode")
	select {
	case deadcodeGate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			releaseDeadcode()
			if prev != "" {
				swapStage(ctx, prev)
			}
			return err
		}
		if prev != "" {
			swapStage(ctx, prev)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func releaseDeadcode() {
	<-deadcodeGate
}

func deadcodeArgs() []string {
	// -filter= keeps dead functions outside the module itself. The default
	// filter hides vendored dependencies, which is where the patched code sits.
	// -generated matches the old -whylive check, which did not skip them.
	// -json lists every unreachable function once; -whylive repeats the whole
	// program for each symbol and keeps the call graph.
	return []string{"-filter=", "-generated", "-json", "./..."}
}

func deadcodeTimeoutOutput() string {
	return "deadcode не уложился в " + minutesRu(deadcodeLimit)
}

func minutesRu(d time.Duration) string {
	n := int(d / time.Minute)
	n10 := n % 10
	n100 := n % 100
	switch {
	case n10 == 1 && n100 != 11:
		return fmt.Sprintf("%d минуту", n)
	case n10 >= 2 && n10 <= 4 && (n100 < 12 || n100 > 14):
		return fmt.Sprintf("%d минуты", n)
	default:
		return fmt.Sprintf("%d минут", n)
	}
}

func classifyModuleSymbol(res moduleDeadcode, symbol string) (string, string) {
	switch res.Status {
	case "ok":
		if _, dead := res.Dead[symbol]; dead {
			return "dead", "функция есть в списке недостижимого кода"
		}
		return "live", "функции нет в списке недостижимого кода"
	case "no-main":
		out := res.Output
		if !strings.Contains(out, "no main packages") {
			out = "deadcode: no main packages"
		}
		return "no-main", out
	default:
		return "failed", res.Output
	}
}

func parseDeadcode(stdout string) (map[string]struct{}, error) {
	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return nil, fmt.Errorf("empty deadcode output")
	}
	var pkgs []struct {
		Path  string `json:"Path"`
		Funcs []struct {
			Name string `json:"Name"`
		} `json:"Funcs"`
	}
	if err := json.Unmarshal([]byte(stdout), &pkgs); err != nil {
		return nil, err
	}
	dead := make(map[string]struct{}, len(pkgs))
	for _, pkg := range pkgs {
		if pkg.Path == "" {
			continue
		}
		for _, fn := range pkg.Funcs {
			if fn.Name == "" {
				continue
			}
			dead[pkg.Path+"."+fn.Name] = struct{}{}
		}
	}
	return dead, nil
}

func trimRunOutput(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 2000 {
		s = s[:2000]
	}
	return s
}

// runGrouped runs name in its own process group and kills that group when ctx
// ends. packages.Load starts go list as a child; killing only deadcode leaves
// the child holding memory.
func runGrouped(ctx context.Context, dir string, env []string, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.WaitDelay = 3 * time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
	}
	cmd.Cancel = func() error { return killGroup(cmd) }
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func killGroup(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return os.ErrProcessDone
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

func deadcodeEnv(ctx context.Context, useVendor bool) []string {
	env := append([]string{}, os.Environ()...)
	if name := toolchainFrom(ctx); name != "" {
		env = setEnv(env, "GOTOOLCHAIN", name)
	}
	env = withMemLimit(env)
	if useVendor {
		env = withVendorMod(env)
	}
	return env
}

func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func withMemLimit(env []string) []string {
	for _, entry := range env {
		if strings.HasPrefix(entry, "GOMEMLIMIT=") && len(strings.TrimPrefix(entry, "GOMEMLIMIT=")) > 0 {
			return env
		}
	}
	limit, ok := cgroupMemoryLimit()
	if !ok {
		return env
	}
	return append(env, "GOMEMLIMIT="+limit)
}

// cgroupMemoryLimit is one slot's share of the cgroup cap, in bytes.
// Three quarters of the cap are reserved for deadcode and then split across
// deadcodeSlots, so two processes cannot each believe they own most of the RAM.
func cgroupMemoryLimit() (string, bool) {
	var paths []string
	if rel := selfCgroupRel(); rel != "" {
		paths = append(paths,
			"/sys/fs/cgroup"+rel+"/memory.max",
			"/sys/fs/cgroup/memory"+rel+"/memory.limit_in_bytes",
		)
	}
	paths = append(paths,
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	)
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if limit, ok := memLimitValue(string(body)); ok {
			return limit, true
		}
	}
	return "", false
}

func selfCgroupRel() string {
	body, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	var v2, memory string
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			v2 = parts[2]
		}
		if parts[1] == "memory" || strings.Contains(","+parts[1]+",", ",memory,") {
			memory = parts[2]
		}
	}
	rel := v2
	if rel == "" {
		rel = memory
	}
	if rel == "" || rel == "/" {
		return ""
	}
	if !strings.HasPrefix(rel, "/") {
		rel = "/" + rel
	}
	return rel
}

func memLimitValue(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "max" {
		return "", false
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || n < 64<<20 || n >= 1<<62 {
		return "", false
	}
	share := n * 3 / 4 / uint64(deadcodeSlots)
	if share < 64<<20 {
		return "", false
	}
	return strconv.FormatUint(share, 10), true
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
