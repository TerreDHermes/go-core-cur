package tasksvc

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
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

func TestSetReviewAndAverage(t *testing.T) {
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := New(st, &recordingQueue{})
	ctx := context.Background()
	if err := st.Create(ctx, task.Task{
		ID: "a", Status: task.StatusCompleted, ComponentURL: "u", Branch: "b",
		CVEID: "c", PackageName: "p", CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Create(ctx, task.Task{
		ID: "b", Status: task.StatusCompleted, ComponentURL: "u", Branch: "b",
		CVEID: "c2", PackageName: "p", CreatedAt: "2026-01-02T00:00:00Z", UpdatedAt: "2026-01-02T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	five := 5
	three := 3
	if err := svc.SetReview(ctx, "a", &five, "совпало"); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetReview(ctx, "b", nil, "только текст"); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetReview(ctx, "a", &three, strings.Repeat("я", 2001)); !errors.Is(err, task.ErrInvalidInput) {
		t.Fatal(err)
	}
	bad := 6
	if err := svc.SetReview(ctx, "a", &bad, ""); !errors.Is(err, task.ErrInvalidInput) {
		t.Fatal(err)
	}
	page, err := svc.Reviews(ctx, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || page.Rated != 1 || page.Average == nil || *page.Average != 5 {
		t.Fatalf("%+v", page)
	}
	if len(page.Items) != 2 || page.Items[0].Review != "только текст" || page.Items[1].Review != "совпало" {
		t.Fatalf("%+v", page.Items)
	}
}

func TestListRejectsUnknownApplicability(t *testing.T) {
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := New(st, &recordingQueue{})
	_, _, err = svc.List(context.Background(), ListFilter{Applicability: "started"})
	if !errors.Is(err, task.ErrInvalidInput) {
		t.Fatal(err)
	}
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
	if got.Model != "env-model" || got.ComponentURL != "https://example.com/r.git" || got.Status != task.StatusPending {
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

func TestOpenMatchesCanonicalURLAndSavedAliases(t *testing.T) {
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := New(st, &recordingQueue{})
	ctx := context.Background()
	first, err := svc.Open(ctx, task.CreateInput{
		ComponentURL: "git@git.slo:dapp/dapp-grafana.git",
		Branch:       "main",
		CVEID:        "GHSA-q7gw-24fr-5p69",
		PackageName:  "pkg",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, first)
	if err != nil || got.ComponentURL != "https://git.slo/dapp/dapp-grafana.git" {
		t.Fatalf("%+v %v", got, err)
	}
	again, err := svc.Open(ctx, task.CreateInput{
		ComponentURL: "https://Git.Slo/dapp/dapp-grafana/",
		Branch:       "main",
		CVEID:        "ghsa-q7gw-24fr-5p69",
		PackageName:  "pkg",
	})
	if err != nil || again != first {
		t.Fatalf("again %s err %v", again, err)
	}
	other, err := svc.Create(ctx, task.CreateInput{
		ComponentURL: "https://git.slo/dapp/dapp-grafana.git",
		Branch:       "main",
		CVEID:        "GHSA-q7gw-24fr-5p69",
		PackageName:  "pkg",
	})
	if err != nil || other == first {
		t.Fatalf("create %s err %v", other, err)
	}
	casePkg, err := svc.Open(ctx, task.CreateInput{
		ComponentURL: "https://git.slo/dapp/dapp-grafana.git",
		Branch:       "main",
		CVEID:        "GHSA-q7gw-24fr-5p69",
		PackageName:  "Pkg",
	})
	if err != nil || casePkg == first {
		t.Fatalf("package %s err %v", casePkg, err)
	}
	missing, err := svc.Check(ctx, task.CreateInput{
		ComponentURL: "https://git.slo/dapp/dapp-grafana",
		Branch:       "main",
		CVEID:        "CVE-2026-128085",
		PackageName:  "pkg",
	})
	if err != nil || missing != task.CheckNotStarted {
		t.Fatalf("before card %s %v", missing, err)
	}
	primary, aliases := task.CVEIdentity("GHSA-q7gw-24fr-5p69", task.CVEPatch{
		CVE:     "GO-2026-6974",
		Aliases: []string{"CVE-2026-128085", "GHSA-q7gw-24fr-5p69"},
	})
	if err := st.SaveCVEIdentity(ctx, first, primary, aliases); err != nil {
		t.Fatal(err)
	}
	found, err := svc.Open(ctx, task.CreateInput{
		ComponentURL: "ssh://git@git.slo/dapp/dapp-grafana",
		Branch:       "main",
		CVEID:        "CVE-2026-128085",
		PackageName:  "pkg",
	})
	if err != nil || found != first {
		t.Fatalf("found %s err %v", found, err)
	}
}

func TestCancelPendingAndFinished(t *testing.T) {
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := New(st, &recordingQueue{})
	svc.now = func() time.Time { return time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC) }
	ctx := context.Background()
	if err := st.Create(ctx, task.Task{
		ID: "q", Status: task.StatusPending,
		ComponentURL: "u", Branch: "b", CVEID: "c", PackageName: "p",
		CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Cancel(ctx, "q"); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, "q")
	if err != nil || got.Status != task.StatusFailed || got.ErrorMsg != task.StoppedMessage || got.Applicability != task.Uncertain {
		t.Fatalf("%+v %v", got, err)
	}
	if err := svc.Cancel(ctx, " missing "); !errors.Is(err, task.ErrNotFound) {
		t.Fatal(err)
	}
	if err := svc.Cancel(ctx, " "); !errors.Is(err, task.ErrInvalidInput) {
		t.Fatal(err)
	}
}

func TestCheckReportsSixResults(t *testing.T) {
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := New(st, &recordingQueue{})
	ctx := context.Background()
	key := task.CreateInput{
		ComponentURL: " https://example.com/r ",
		Branch:       "main",
		CVEID:        "CVE-1",
		PackageName:  "pkg",
	}

	got, err := svc.Check(ctx, key)
	if err != nil || got != task.CheckNotStarted {
		t.Fatalf("missing: %s %v", got, err)
	}
	if _, err := svc.Check(ctx, task.CreateInput{ComponentURL: "https://example.com/r"}); !errors.Is(err, task.ErrInvalidInput) {
		t.Fatal(err)
	}

	rows := []task.Task{
		{ID: "pending", Status: task.StatusPending, CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z"},
		{ID: "running", Status: task.StatusRunning, CreatedAt: "2026-01-02T00:00:00Z", UpdatedAt: "2026-01-02T00:00:00Z"},
		{ID: "failed", Status: task.StatusFailed, Applicability: task.Uncertain, CreatedAt: "2026-01-03T00:00:00Z", UpdatedAt: "2026-01-03T00:00:00Z"},
		{ID: "applicable", Status: task.StatusCompleted, Applicability: task.Applicable, CreatedAt: "2026-01-04T00:00:00Z", UpdatedAt: "2026-01-04T00:00:00Z"},
		{ID: "not", Status: task.StatusCompleted, Applicability: task.NotApplicable, CreatedAt: "2026-01-05T00:00:00Z", UpdatedAt: "2026-01-05T00:00:00Z"},
		{ID: "uncertain", Status: task.StatusCompleted, Applicability: task.Uncertain, CreatedAt: "2026-01-06T00:00:00Z", UpdatedAt: "2026-01-06T00:00:00Z"},
	}
	want := []string{
		task.CheckInProgress,
		task.CheckInProgress,
		task.CheckFailed,
		task.Applicable,
		task.NotApplicable,
		task.Uncertain,
	}
	for i, row := range rows {
		row.ComponentURL = "https://example.com/r"
		row.Branch = "main"
		row.CVEID = "CVE-1"
		row.PackageName = "pkg"
		if err := st.Create(ctx, row); err != nil {
			t.Fatal(err)
		}
		got, err := svc.Check(ctx, key)
		if err != nil || got != want[i] {
			t.Fatalf("%s: got %s err %v", row.ID, got, err)
		}
	}
}
