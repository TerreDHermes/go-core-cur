package worker

import (
	"context"
	"strings"
	"testing"
	"time"

	"cve-patch-viewer/internal/applicability/ai"
	"cve-patch-viewer/internal/applicability/scan"
	"cve-patch-viewer/internal/applicability/store/sqlite"
	"cve-patch-viewer/internal/applicability/task"
	"cve-patch-viewer/internal/applicability/tasksvc"
)

type pathClone struct {
	dir string
}

func (p pathClone) Clone(context.Context, string, string) (string, error) {
	return p.dir, nil
}

func (p pathClone) Remove(string) {}

type staticScan struct{}

func (staticScan) Scan(context.Context, scan.Input) ([]task.ModuleResult, error) {
	return []task.ModuleResult{{
		GoModPath: "./go.mod",
		Verdict:   "pkg listed in ./go.mod",
		ReportMD:  task.Report{GoModPath: "./go.mod", MatchingLines: []string{"require pkg"}},
	}}, nil
}

func TestWorkerCompletesClaimedTask(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	now := "2026-01-01T00:00:00Z"
	if err := st.Create(context.Background(), task.Task{
		ID: "t1", Status: task.StatusPending,
		ComponentURL: "https://example.com/r", Branch: "main",
		CVEID: "CVE-1", PackageName: "pkg",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	p := New(st, pathClone{dir: t.TempDir()}, staticScan{}, 1, 4, time.Second, nil)
	p.handle("t1")

	got, err := st.Get(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != task.StatusCompleted || len(got.Modules) != 1 || got.Modules[0].ReportMD.GoModPath != "./go.mod" {
		t.Fatalf("%+v", got)
	}

	p.handle("t1")
	got, err = st.Get(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != task.StatusCompleted {
		t.Fatalf("second handle changed status: %+v", got)
	}
	if got.AICalls != 0 || got.AIMinMS != nil || got.AIMaxMS != nil {
		t.Fatalf("metrics %+v", got)
	}
}

type countingScan struct{}

func (countingScan) Scan(ctx context.Context, _ scan.Input) ([]task.ModuleResult, error) {
	stats := ai.CallStatsFrom(ctx)
	stats.Observe(10 * time.Millisecond)
	stats.Observe(40 * time.Millisecond)
	return []task.ModuleResult{{
		GoModPath: "./go.mod",
		Verdict:   "pkg listed in ./go.mod",
	}}, nil
}

type switchedScan struct{}

func (switchedScan) Scan(context.Context, scan.Input) ([]task.ModuleResult, error) {
	return []task.ModuleResult{{
		GoModPath: "./go.mod",
		Verdict:   "ok",
		ReportMD: task.Report{
			ActiveModel: "Qwen/Qwen3.6-35B-A3B",
			ModelNote:   "Модель сменена с primary на Qwen/Qwen3.6-35B-A3B: очередь AI HUB переполнена.",
		},
	}}, nil
}

func TestHandleStoresSwitchedModel(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := "2026-01-01T00:00:00Z"
	if err := st.Create(context.Background(), task.Task{
		ID: "t1", Status: task.StatusPending,
		ComponentURL: "https://example.com/r", Branch: "main",
		CVEID: "CVE-1", PackageName: "pkg", Model: "primary",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	p := New(st, pathClone{dir: t.TempDir()}, switchedScan{}, 1, 4, time.Second, nil)
	p.handle("t1")
	got, err := st.Get(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != task.StatusCompleted || got.Model != "Qwen/Qwen3.6-35B-A3B" {
		t.Fatalf("%s %s", got.Status, got.Model)
	}
	if !strings.Contains(got.Modules[0].ReportMD.PublicText(), "очередь AI HUB переполнена") {
		t.Fatal(got.Modules[0].ReportMD.PublicText())
	}
}

type deadlineScan struct{}

func (deadlineScan) Scan(ctx context.Context, _ scan.Input) ([]task.ModuleResult, error) {
	if stats := ai.CallStatsFrom(ctx); stats != nil {
		stats.Observe(12 * time.Millisecond)
		stats.Observe(40 * time.Millisecond)
	}
	if p := scan.ProgressFrom(ctx); p != nil {
		p.At("проверка достижимости", "example.com/pkg.Func", 2, 8)
		p.SetGoMods(17)
	}
	return nil, context.DeadlineExceeded
}

func TestDeadlineKeepsCloneAndAIStats(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := "2026-01-01T00:00:00Z"
	if err := st.Create(context.Background(), task.Task{
		ID: "t1", Status: task.StatusPending,
		ComponentURL: "https://example.com/r", Branch: "main",
		CVEID: "CVE-1", PackageName: "pkg",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	p := New(st, pathClone{dir: t.TempDir()}, deadlineScan{}, 1, 4, time.Minute, nil)
	p.handle("t1")
	got, err := st.Get(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != task.StatusFailed || !strings.Contains(got.ErrorMsg, "deadline exceeded") {
		t.Fatalf("%s %s", got.Status, got.ErrorMsg)
	}
	if got.CloneMS == nil || *got.CloneMS < 0 {
		t.Fatalf("clone %v", got.CloneMS)
	}
	if got.AICalls != 2 || got.AIMinMS == nil || *got.AIMinMS != 12 || got.AIMaxMS == nil || *got.AIMaxMS != 40 {
		t.Fatalf("calls %d min %v max %v", got.AICalls, got.AIMinMS, got.AIMaxMS)
	}
	if got.GoModCount == nil || *got.GoModCount != 17 || !strings.Contains(got.StopStage, "Найдено go.mod: 17") || !strings.Contains(got.ErrorMsg, "проверка достижимости") {
		t.Fatalf("mods %v stage %s err %s", got.GoModCount, got.StopStage, got.ErrorMsg)
	}
}

func TestHandleStoresAICallTimes(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := "2026-01-01T00:00:00Z"
	if err := st.Create(context.Background(), task.Task{
		ID: "t1", Status: task.StatusPending,
		ComponentURL: "https://example.com/r", Branch: "main",
		CVEID: "CVE-1", PackageName: "pkg",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	p := New(st, pathClone{dir: t.TempDir()}, countingScan{}, 1, 4, time.Second, nil)
	p.handle("t1")
	got, err := st.Get(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != task.StatusCompleted || got.AICalls != 2 || got.AIMinMS == nil || *got.AIMinMS != 10 || got.AIMaxMS == nil || *got.AIMaxMS != 40 {
		t.Fatalf("%+v min %v max %v", got.Status, got.AIMinMS, got.AIMaxMS)
	}
}

type gateScan struct {
	started chan struct{}
}

func (g gateScan) Scan(ctx context.Context, _ scan.Input) ([]task.ModuleResult, error) {
	if stats := ai.CallStatsFrom(ctx); stats != nil {
		stats.Observe(5 * time.Millisecond)
	}
	close(g.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestCancelStopsTheRunningAnalysis(t *testing.T) {
	st, err := sqlite.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := "2026-01-01T00:00:00Z"
	if err := st.Create(context.Background(), task.Task{
		ID: "t1", Status: task.StatusPending,
		ComponentURL: "https://example.com/r", Branch: "main",
		CVEID: "CVE-1", PackageName: "pkg",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	p := New(st, pathClone{dir: t.TempDir()}, gateScan{started: started}, 1, 4, time.Minute, nil)
	svc := tasksvc.New(st, p)
	done := make(chan struct{})
	go func() {
		p.handle("t1")
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not start")
	}
	if err := svc.Cancel(context.Background(), "t1"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancel did not stop the worker")
	}
	got, err := st.Get(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != task.StatusFailed || got.ErrorMsg != task.StoppedMessage {
		t.Fatalf("%+v", got)
	}
	if got.AICalls != 1 || got.AIMinMS == nil || *got.AIMinMS != 5 {
		t.Fatalf("calls %d min %v", got.AICalls, got.AIMinMS)
	}
	if err := svc.Cancel(context.Background(), "t1"); err != task.ErrNotCancellable {
		t.Fatal(err)
	}
}
