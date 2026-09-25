package worker

import (
	"context"
	"testing"
	"time"

	"cveanalysis/internal/scan"
	"cveanalysis/internal/store/sqlite"
	"cveanalysis/internal/task"
)

type pathClone struct {
	dir string
}

func (p pathClone) Clone(context.Context, string, string) (string, error) {
	return p.dir, nil
}

func (p pathClone) Remove(string) {}

type staticScan struct{}

func (staticScan) Scan(context.Context, scan.Input) (scan.Result, error) {
	return scan.Result{Verdict: "found 1 go.mod", ReportMD: "./go.mod\n"}, nil
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
	if got.Status != task.StatusCompleted || got.ReportMD != "./go.mod\n" {
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
}
