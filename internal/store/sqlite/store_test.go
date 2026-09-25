package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"cveanalysis/internal/task"
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
	if err := st.Complete(ctx, item.ID, "found 1 go.mod", "./go.mod\n", "2026-01-01T00:00:03Z"); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != task.StatusCompleted || got.Verdict != "found 1 go.mod" || got.ReportMD != "./go.mod\n" {
		t.Fatalf("%+v", got)
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
	if all[0].ErrorMsg != "" || all[0].Verdict != "" {
		t.Fatalf("list leaked fields: %+v", all[0])
	}
	pending, err := st.ListPendingIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0] != "a" {
		t.Fatalf("%v", pending)
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
