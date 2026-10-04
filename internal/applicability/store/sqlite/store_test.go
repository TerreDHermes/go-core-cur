package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"cve-patch-viewer/internal/applicability/task"
)

func TestClaimIsAtomic(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	item := task.Task{
		ID: "id-1", Status: task.StatusPending,
		ComponentURL: "https://example.com/r.git", Branch: "main",
		CVEID: "CVE-1", PackageName: "pkg",
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
	if got.Status != task.StatusCompleted || len(got.Modules) != 1 || got.Modules[0].GoModPath != "./go.mod" {
		t.Fatalf("%+v", got)
	}
	if got.Applicability != task.Uncertain {
		t.Fatal(got.Applicability)
	}
	ms := got.DurationMS()
	if ms == nil || *ms != 3000 {
		t.Fatalf("created %s updated %s duration %v", got.CreatedAt, got.UpdatedAt, ms)
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
	ms := failed.DurationMS()
	if ms == nil || *ms != 2000 {
		t.Fatalf("created %s updated %s duration %v", failed.CreatedAt, failed.UpdatedAt, ms)
	}
	pending, err := st.ListPendingIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0] != "a" {
		t.Fatalf("%v", pending)
	}
}

func TestListUsesModuleVerdictWhenApplicabilityColumnIsEmpty(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	item := task.Task{
		ID: "old", Status: task.StatusPending,
		ComponentURL: "u", Branch: "b", CVEID: "c", PackageName: "p",
		CreatedAt: "2026-01-03T00:00:00Z", UpdatedAt: "2026-01-03T00:00:00Z",
	}
	if err := st.Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Claim(ctx, item.ID, "2026-01-03T00:00:01Z"); err != nil {
		t.Fatal(err)
	}
	modules := []task.ModuleResult{
		{GoModPath: "./go.mod", Verdict: "Уязвимость неприменима к компоненту."},
		{GoModPath: "./scripts/go.mod", Verdict: "Уязвимость неприменима к компоненту."},
	}
	if err := st.Complete(ctx, item.ID, modules, "2026-01-03T00:00:02Z"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE analysis_tasks SET applicability = '' WHERE id = ?`, item.ID); err != nil {
		t.Fatal(err)
	}

	listed, err := st.List(ctx, "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := listed[0].PublicApplicability()
	if got == nil || *got != task.NotApplicable {
		t.Fatalf("list applicability %v", got)
	}

	if _, err := st.db.ExecContext(ctx, `UPDATE analysis_tasks SET applicability = ? WHERE id = ?`, task.Applicable, item.ID); err != nil {
		t.Fatal(err)
	}
	listed, err = st.List(ctx, "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	got = listed[0].PublicApplicability()
	if got == nil || *got != task.Applicable || len(listed[0].Modules) != 0 {
		t.Fatalf("stored %v modules %d", got, len(listed[0].Modules))
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
