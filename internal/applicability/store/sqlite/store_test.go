package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"cve-patch-viewer/internal/applicability/task"
)

func TestClaimIsAtomic(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	item := task.Task{
		ID: "id-1", Status: task.StatusPending,
		ComponentURL: "https://example.com/r.git", Branch: "main",
		CVEID: "CVE-1", PackageName: "pkg", Model: "env-model",
		CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z",
	}
	if err := st.Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	ok, err := st.Claim(ctx, item.ID, "2026-01-01T00:00:01Z")
	if err != nil || !ok {
		t.Fatalf("first claim ok=%v err=%v", ok, err)
	}
	ok, err = st.Claim(ctx, item.ID, "2026-01-01T00:00:02Z")
	if err != nil || ok {
		t.Fatalf("second claim ok=%v err=%v", ok, err)
	}
	modules := []task.ModuleResult{{
		GoModPath: "./go.mod",
		Verdict:   "pkg listed in ./go.mod",
		ReportMD:  task.Report{GoModPath: "./go.mod", HasVendor: true, VendorPath: "./vendor"},
	}}
	if err := st.Complete(ctx, item.ID, modules, "2026-01-01T00:00:03Z"); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != task.StatusCompleted || got.Model != "env-model" || len(got.Modules) != 1 || got.Modules[0].GoModPath != "./go.mod" {
		t.Fatalf("%+v", got)
	}
	if got.Applicability != task.Uncertain {
		t.Fatal(got.Applicability)
	}
	if got.StartedAt != "2026-01-01T00:00:01Z" {
		t.Fatal(got.StartedAt)
	}
	ms := got.DurationMS(time.Time{})
	if ms == nil || *ms != 2000 {
		t.Fatalf("started %s updated %s duration %v", got.StartedAt, got.UpdatedAt, ms)
	}
}

func TestListOmitsHeavyFieldsAndOrdersByCreatedAt(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	for _, item := range []task.Task{
		{ID: "a", Status: task.StatusPending, ComponentURL: "u", Branch: "b", CVEID: "c", PackageName: "p", CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z"},
		{ID: "b", Status: task.StatusPending, ComponentURL: "u", Branch: "b", CVEID: "c", PackageName: "p", CreatedAt: "2026-01-02T00:00:00Z", UpdatedAt: "2026-01-02T00:00:00Z"},
	} {
		if err := st.Create(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Claim(ctx, "b", "2026-01-02T00:00:01Z"); err != nil {
		t.Fatal(err)
	}
	if err := st.Fail(ctx, "b", "clone failed", "2026-01-02T00:00:02Z"); err != nil {
		t.Fatal(err)
	}

	all, err := st.List(ctx, "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].ID != "b" || all[1].ID != "a" {
		t.Fatalf("%+v", all)
	}
	if all[0].ErrorMsg != "" || len(all[0].Modules) != 0 {
		t.Fatalf("list leaked fields: %+v", all[0])
	}
	total, err := st.Count(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("total %d", total)
	}
	pendingCount, err := st.Count(ctx, task.StatusPending)
	if err != nil {
		t.Fatal(err)
	}
	if pendingCount != 1 {
		t.Fatalf("pending %d", pendingCount)
	}
	page, err := st.List(ctx, "", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || page[0].ID != "a" || total != 2 {
		t.Fatalf("page %+v total %d", page, total)
	}
	failed, err := st.Get(ctx, "b")
	if err != nil {
		t.Fatal(err)
	}
	if failed.Applicability != task.Uncertain {
		t.Fatal(failed.Applicability)
	}
	if failed.StartedAt != "2026-01-02T00:00:01Z" {
		t.Fatal(failed.StartedAt)
	}
	ms := failed.DurationMS(time.Time{})
	if ms == nil || *ms != 1000 {
		t.Fatalf("started %s updated %s duration %v", failed.StartedAt, failed.UpdatedAt, ms)
	}
	pending, err := st.ListPendingIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0] != "a" {
		t.Fatalf("%v", pending)
	}

	latest, err := st.LatestID(ctx, "u", "b", "c", "p")
	if err != nil || latest != "b" {
		t.Fatalf("latest %s err %v", latest, err)
	}
	if _, err := st.LatestID(ctx, "u", "b", "c", "other"); err != task.ErrNotFound {
		t.Fatal(err)
	}
}

func TestRequeueRunningAndAIMetrics(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	for _, item := range []task.Task{
		{ID: "run", Status: task.StatusPending, ComponentURL: "u", Branch: "b", CVEID: "c", PackageName: "p", CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z"},
		{ID: "wait", Status: task.StatusPending, ComponentURL: "u", Branch: "b", CVEID: "c", PackageName: "p", CreatedAt: "2026-01-02T00:00:00Z", UpdatedAt: "2026-01-02T00:00:00Z"},
		{ID: "done", Status: task.StatusFailed, ComponentURL: "u", Branch: "b", CVEID: "c", PackageName: "p", CreatedAt: "2026-01-03T00:00:00Z", UpdatedAt: "2026-01-03T00:00:00Z"},
	} {
		if err := st.Create(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	if ok, err := st.Claim(ctx, "run", "2026-01-01T00:00:02Z"); err != nil || !ok {
		t.Fatalf("claim ok=%v err=%v", ok, err)
	}
	if err := st.SaveCloneMS(ctx, "run", 1500); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveAIMetrics(ctx, "run", task.AIMetrics{Calls: 4, MinMS: 10, MaxMS: 20}); err != nil {
		t.Fatal(err)
	}
	n := 17
	if err := st.SaveProgress(ctx, "run", &n, "Остановились на этапе «поиск go.mod». Найдено go.mod: 17."); err != nil {
		t.Fatal(err)
	}
	ids, err := st.RequeueRunning(ctx, "2026-01-04T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "run" {
		t.Fatalf("%v", ids)
	}
	got, err := st.Get(ctx, "run")
	if err != nil || got.Status != task.StatusPending || got.StartedAt != "" || got.CloneMS != nil || got.AICalls != 0 || got.AIMinMS != nil || got.AIMaxMS != nil || got.GoModCount != nil || got.StopStage != "" {
		t.Fatalf("%+v %v", got, err)
	}
	pending, err := st.ListPendingIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 || pending[0] != "run" || pending[1] != "wait" {
		t.Fatalf("%v", pending)
	}
	failed, err := st.Get(ctx, "done")
	if err != nil || failed.Status != task.StatusFailed {
		t.Fatalf("%+v", failed)
	}

	if err := st.SaveAIMetrics(ctx, "run", task.AIMetrics{Calls: 2, MinMS: 15, MaxMS: 900}); err != nil {
		t.Fatal(err)
	}
	got, err = st.Get(ctx, "run")
	if err != nil || got.AICalls != 2 || got.AIMinMS == nil || *got.AIMinMS != 15 || got.AIMaxMS == nil || *got.AIMaxMS != 900 {
		t.Fatalf("%+v", got)
	}
	if err := st.SaveAIMetrics(ctx, "run", task.AIMetrics{}); err != nil {
		t.Fatal(err)
	}
	got, err = st.Get(ctx, "run")
	if err != nil || got.AICalls != 2 || got.AIMinMS == nil || *got.AIMinMS != 15 || got.AIMaxMS == nil || *got.AIMaxMS != 900 {
		t.Fatalf("%+v", got)
	}

	ok, err := st.Cancel(ctx, "wait", task.StoppedMessage, "2026-01-05T00:00:00Z")
	if err != nil || !ok {
		t.Fatalf("ok %v err %v", ok, err)
	}
	stopped, err := st.Get(ctx, "wait")
	if err != nil || stopped.Status != task.StatusFailed || stopped.ErrorMsg != task.StoppedMessage || stopped.Applicability != task.Uncertain {
		t.Fatalf("%+v", stopped)
	}
	ok, err = st.Cancel(ctx, "wait", task.StoppedMessage, "2026-01-06T00:00:00Z")
	if err != nil || ok {
		t.Fatalf("second cancel ok %v err %v", ok, err)
	}
}

func openTest(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}
