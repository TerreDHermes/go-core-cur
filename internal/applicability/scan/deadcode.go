package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// deadcodeLimit is the budget of one reachability check. The task deadline is
// separate and still ends the whole analysis. Past this limit the run is stopped
// and reachability stays unknown, so the model can still write a verdict.
// The clock starts after a slot is acquired, so time spent waiting does not count.
// Listing main packages and, when a main does not compile, one repeat run share
// this same budget.
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
// Loaded is the import set of the main packages that were actually built.
// Nil means the whole module pattern was loaded, so a symbol absent from Dead
// is live. Skipped lists main packages dropped because they do not compile.
// BrokenFiles are the source files named by the compiler.
type moduleDeadcode struct {
	Status      string
	Dead        map[string]struct{}
	Output      string
	Loaded      map[string]struct{}
	Skipped     []string
	BrokenFiles []string
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
	graph, graphErr := loadModuleGraph(ctx, moduleDir, env)
	if ctx.Err() != nil {
		return deadcodeStopped(ctx, started, graphErr)
	}
	mains := mainPackages(graph)
	if graphErr != nil || len(graph) == 0 {
		return runDeadcode(ctx, started, moduleDir, env, bin, []string{"./..."}, nil, nil)
	}
	if len(mains) == 0 {
		return moduleDeadcode{Status: "no-main", Output: "deadcode: no main packages"}
	}
	first := runDeadcode(ctx, started, moduleDir, env, bin, mainPatterns(moduleDir, mains), nil, nil)
	if first.Status != "failed" || !compileFailure(first.Output) {
		if first.Status == "ok" {
			return withProgramDeps(ctx, started, moduleDir, env, mainPatterns(moduleDir, mains), first)
		}
		return first
	}
	scanText := compileScanText(first)
	kept, dropped, broken := dropBrokenMains(moduleDir, graph, mains, scanText)
	if len(dropped) == 0 && len(broken) > 0 && ctx.Err() == nil {
		deps, err := loadDepsGraph(ctx, moduleDir, env, mainPatterns(moduleDir, mains))
		if ctx.Err() != nil {
			return deadcodeStopped(ctx, started, err)
		}
		if len(deps) > 0 {
			kept, dropped, broken = dropBrokenMains(moduleDir, deps, mains, scanText)
		}
	}
	if len(dropped) == 0 || len(kept) == 0 || ctx.Err() != nil {
		if ctx.Err() != nil {
			return deadcodeStopped(ctx, started, errors.New(first.Output))
		}
		if len(kept) == 0 && len(dropped) > 0 {
			return moduleDeadcode{
				Status:      "failed",
				Output:      "ни один main не собрался. " + skippedMainsNote(dropped),
				Skipped:     dropped,
				BrokenFiles: broken,
			}
		}
		first.BrokenFiles = broken
		return first
	}
	second := runDeadcode(ctx, started, moduleDir, env, bin, mainPatterns(moduleDir, kept), dropped, broken)
	if second.Status == "ok" {
		return withProgramDeps(ctx, started, moduleDir, env, mainPatterns(moduleDir, kept), second)
	}
	return second
}

func withProgramDeps(ctx context.Context, started time.Time, moduleDir string, env []string, patterns []string, res moduleDeadcode) moduleDeadcode {
	loaded, err := dependencySet(ctx, moduleDir, env, patterns)
	if ctx.Err() != nil {
		return deadcodeStopped(ctx, started, err)
	}
	if err != nil || len(loaded) == 0 {
		return moduleDeadcode{Status: "failed", Output: "не удалось получить список пакетов программы", Skipped: res.Skipped, BrokenFiles: res.BrokenFiles}
	}
	res.Loaded = loaded
	return res
}

func dependencySet(ctx context.Context, moduleDir string, env []string, patterns []string) (map[string]struct{}, error) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		return nil, fmt.Errorf("команда go недоступна")
	}
	args := append([]string{"list", "-e", "-f", "{{.ImportPath}}", "-deps"}, patterns...)
	stdout, stderr, err := runGrouped(ctx, moduleDir, env, goBin, args...)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	set := map[string]struct{}{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			set[line] = struct{}{}
		}
	}
	if len(set) == 0 {
		msg := strings.TrimSpace(stderr)
		if msg == "" && err != nil {
			msg = err.Error()
		}
		if msg == "" {
			msg = "go list не вернул пакеты"
		}
		return nil, fmt.Errorf("%s", trimRunOutput(msg))
	}
	return set, nil
}

func runDeadcode(ctx context.Context, started time.Time, moduleDir string, env []string, bin string, patterns, skipped, broken []string) moduleDeadcode {
	args := append(deadcodeArgs(), patterns...)
	stdout, stderr, err := runGrouped(ctx, moduleDir, env, bin, args...)
	res := interpretDeadcode(ctx, started, stdout, stderr, err)
	res.Skipped = skipped
	if len(broken) > 0 {
		res.BrokenFiles = broken
	}
	return res
}

func interpretDeadcode(ctx context.Context, started time.Time, stdout, stderr string, err error) moduleDeadcode {
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
	return moduleDeadcode{Status: "failed", Output: trimRunOutput(out), BrokenFiles: filesFromCompileError(out)}
}

func deadcodeStopped(ctx context.Context, started time.Time, err error) moduleDeadcode {
	if time.Since(started) >= deadcodeLimit-2*time.Second {
		return moduleDeadcode{Status: "failed", Output: deadcodeTimeoutOutput()}
	}
	out := ""
	if err != nil {
		out = err.Error()
	}
	if out == "" && ctx.Err() != nil {
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
	// The package pattern is added by the caller: every main, or ./... when
	// the main list could not be built.
	return []string{"-filter=", "-generated", "-json"}
}

type listedPackage struct {
	ImportPath string
	Name       string
	Dir        string
	Imports    []string
}

func loadDepsGraph(ctx context.Context, moduleDir string, env []string, patterns []string) ([]listedPackage, error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("нет пакетов")
	}
	return loadListed(ctx, moduleDir, env, append([]string{"list", "-e", "-json", "-deps"}, patterns...))
}

func loadModuleGraph(ctx context.Context, moduleDir string, env []string) ([]listedPackage, error) {
	return loadListed(ctx, moduleDir, env, []string{"list", "-e", "-json", "./..."})
}

func loadListed(ctx context.Context, moduleDir string, env []string, args []string) ([]listedPackage, error) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		return nil, fmt.Errorf("команда go недоступна")
	}
	stdout, stderr, err := runGrouped(ctx, moduleDir, env, goBin, args...)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	pkgs, perr := parseGoListJSON(stdout)
	if len(pkgs) > 0 {
		return pkgs, nil
	}
	if perr != nil {
		return nil, perr
	}
	if err != nil {
		msg := strings.TrimSpace(stderr)
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%s", trimRunOutput(msg))
	}
	return nil, fmt.Errorf("go list не вернул пакеты")
}

func parseGoListJSON(stdout string) ([]listedPackage, error) {
	dec := json.NewDecoder(strings.NewReader(stdout))
	var out []listedPackage
	for {
		var pkg listedPackage
		err := dec.Decode(&pkg)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if pkg.ImportPath != "" {
			out = append(out, pkg)
		}
	}
	return out, nil
}

func mainPackages(pkgs []listedPackage) []listedPackage {
	var mains []listedPackage
	for _, pkg := range pkgs {
		if pkg.Name == "main" && pkg.Dir != "" && pkg.ImportPath != "" {
			mains = append(mains, pkg)
		}
	}
	sort.Slice(mains, func(i, j int) bool { return mains[i].ImportPath < mains[j].ImportPath })
	return mains
}

func importPaths(pkgs []listedPackage) []string {
	out := make([]string, 0, len(pkgs))
	for _, pkg := range pkgs {
		out = append(out, pkg.ImportPath)
	}
	return out
}

func mainPatterns(moduleDir string, mains []listedPackage) []string {
	var patterns []string
	for _, main := range mains {
		rel, err := filepath.Rel(moduleDir, main.Dir)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		if rel == ".." || strings.HasPrefix(rel, "../") {
			continue
		}
		if rel == "." {
			patterns = append(patterns, ".")
			continue
		}
		patterns = append(patterns, "./"+rel)
	}
	sort.Strings(patterns)
	return patterns
}

func importClosure(pkgs []listedPackage, roots []string) map[string]struct{} {
	byPath := make(map[string]listedPackage, len(pkgs))
	for _, pkg := range pkgs {
		byPath[pkg.ImportPath] = pkg
	}
	seen := map[string]struct{}{}
	var walk func(string)
	walk = func(path string) {
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		pkg, ok := byPath[path]
		if !ok {
			return
		}
		for _, imp := range pkg.Imports {
			walk(imp)
		}
	}
	for _, root := range roots {
		walk(root)
	}
	return seen
}

var compileFile = regexp.MustCompile(`(?m)([^\s:]+\.go):\d+(?::\d+)?:`)

func filesFromCompileError(out string) []string {
	var files []string
	seen := map[string]struct{}{}
	for _, match := range compileFile.FindAllStringSubmatch(out, -1) {
		file := match[1]
		if _, ok := seen[file]; ok {
			continue
		}
		seen[file] = struct{}{}
		files = append(files, file)
	}
	return files
}

func compileFailure(out string) bool {
	return strings.Contains(out, "packages contain errors") || len(filesFromCompileError(out)) > 0
}

func packageForFile(pkgs []listedPackage, file string) (string, bool) {
	file = filepath.Clean(file)
	bestLen := -1
	best := ""
	for _, pkg := range pkgs {
		if pkg.Dir == "" || pkg.ImportPath == "" {
			continue
		}
		dir := filepath.Clean(pkg.Dir)
		rel, err := filepath.Rel(dir, file)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		if len(dir) > bestLen {
			bestLen = len(dir)
			best = pkg.ImportPath
		}
	}
	return best, best != ""
}

// vendorImportPath reads a dependency import path from a file under vendor/.
// go list ./... does not list those packages, so the compiler path is the source.
func vendorImportPath(moduleDir, file string) (string, bool) {
	rel, err := filepath.Rel(moduleDir, file)
	if err != nil {
		return "", false
	}
	rel = filepath.ToSlash(rel)
	const marker = "vendor/"
	i := strings.Index(rel, marker)
	if i < 0 {
		return "", false
	}
	dir := filepath.ToSlash(filepath.Dir(filepath.FromSlash(rel[i+len(marker):])))
	if dir == "." || dir == "" || strings.HasPrefix(dir, "../") {
		return "", false
	}
	return dir, true
}

// dropBrokenMains removes mains that import a package named by the compiler.
// kept is what the second deadcode run builds. dropped are the patterns that
// were removed. broken are the source files from the error.
func dropBrokenMains(moduleDir string, pkgs, mains []listedPackage, errOut string) (kept []listedPackage, dropped []string, broken []string) {
	broken = filesFromCompileError(errOut)
	if len(broken) == 0 {
		return mains, nil, nil
	}
	bad := map[string]struct{}{}
	for _, file := range broken {
		if path, ok := packageForFile(pkgs, file); ok {
			bad[path] = struct{}{}
			continue
		}
		if path, ok := vendorImportPath(moduleDir, file); ok {
			bad[path] = struct{}{}
		}
	}
	if len(bad) == 0 {
		return mains, nil, broken
	}
	for _, main := range mains {
		reach := importClosure(pkgs, []string{main.ImportPath})
		drop := false
		for path := range bad {
			if _, ok := reach[path]; ok {
				drop = true
				break
			}
		}
		if drop {
			dropped = append(dropped, mainPatterns(moduleDir, []listedPackage{main})...)
			continue
		}
		kept = append(kept, main)
	}
	sort.Strings(dropped)
	return kept, dropped, broken
}

func compileScanText(res moduleDeadcode) string {
	text := res.Output
	for _, file := range res.BrokenFiles {
		if file != "" && !strings.Contains(text, file) {
			text += "\n" + file + ":1:1: broken"
		}
	}
	return text
}

func skippedMainsNote(patterns []string) string {
	if len(patterns) == 0 {
		return ""
	}
	return "Из сборки убраны main, которые не собираются: " + strings.Join(patterns, ", ")
}

func symbolLoaded(loaded map[string]struct{}, symbol string) bool {
	best := ""
	for pkg := range loaded {
		if strings.HasPrefix(symbol, pkg+".") && len(pkg) > len(best) {
			best = pkg
		}
	}
	return best != ""
}

func fileNamedIn(file string, broken []string) bool {
	file = strings.TrimPrefix(filepath.ToSlash(filepath.Clean(file)), "./")
	for _, name := range broken {
		name = strings.TrimPrefix(filepath.ToSlash(filepath.Clean(name)), "./")
		if file == name || strings.HasSuffix(name, "/"+file) || strings.HasSuffix(file, "/"+name) {
			return true
		}
	}
	return false
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
		if res.Loaded != nil && !symbolLoaded(res.Loaded, symbol) {
			return "missing", "функция не входит в программы, которые собираются"
		}
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
