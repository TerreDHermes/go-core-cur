package tasksvc

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"cve-patch-viewer/internal/applicability/store/sqlite"
	"cve-patch-viewer/internal/applicability/task"
)

type recordingQueue struct {
	ids []string
}

func (q *recordingQueue) Enqueue(_ context.Context, id string) error {
	q.ids = append(q.ids, id)
	return nil
}

func TestOpenReusesLatestOrCreates(t *testing.T) {
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	q := &recordingQueue{}
	svc := New(st, q)
	svc.SetDefaultModel("env-model")
	svc.now = func() time.Time { return time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC) }

	in := task.CreateInput{
		ComponentURL: " https://example.com/r ",
		Branch:       "main",
		CVEID:        "CVE-1",
		PackageName:  "pkg",
		Model:        "should-be-ignored",
	}
	ctx := context.Background()
	first, err := svc.Open(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Open(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if first == "" || first != second {
		t.Fatalf("first %s second %s", first, second)
	}
	if len(q.ids) != 1 || q.ids[0] != first {
		t.Fatalf("queue %#v", q.ids)
	}
	got, err := st.Get(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if got.Model != "env-model" || got.ComponentURL != "https://example.com/r" || got.Status != task.StatusPending {
		t.Fatalf("%+v", got)
	}

	if err := st.Create(ctx, task.Task{
		ID: "failed-newer", Status: task.StatusFailed,
		ComponentURL: "https://example.com/r", Branch: "main",
		CVEID: "CVE-1", PackageName: "pkg", Model: "old-model",
		CreatedAt: "2026-01-04T00:00:00Z", UpdatedAt: "2026-01-04T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	latest, err := svc.Open(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if latest != "failed-newer" || len(q.ids) != 1 {
		t.Fatalf("latest %s queue %#v", latest, q.ids)
	}

	other, err := svc.Open(ctx, task.CreateInput{
		ComponentURL: "https://example.com/r",
		Branch:       "main",
		CVEID:        "ALIAS-1",
		PackageName:  "pkg",
	})
	if err != nil {
		t.Fatal(err)
	}
	if other == latest || len(q.ids) != 2 {
		t.Fatalf("other %s queue %#v", other, q.ids)
	}

	_, err = svc.Open(ctx, task.CreateInput{ComponentURL: "https://example.com/r"})
	if !errors.Is(err, task.ErrInvalidInput) {
		t.Fatal(err)
	}
}
