package tasksvc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"cve-patch-viewer/internal/applicability/gitrepo"
	"cve-patch-viewer/internal/applicability/store"
	"cve-patch-viewer/internal/applicability/task"

	"github.com/google/uuid"
)

type Enqueuer interface {
	Enqueue(ctx context.Context, taskID string) error
}

type Service struct {
	store        store.Store
	queue        Enqueuer
	now          func() time.Time
	defaultModel string
}

// SetDefaultModel is the model from AI_MODEL. Create uses it when the request omits a model.
func (s *Service) SetDefaultModel(model string) {
	s.defaultModel = strings.TrimSpace(model)
}

func New(st store.Store, queue Enqueuer) *Service {
	return &Service{store: st, queue: queue, now: time.Now}
}

type ListFilter struct {
	Status        task.Status
	ComponentURL  string
	Branch        string
	CVEID         string
	PackageName   string
	Applicability string
	Limit         int
	Offset        int
}

func (s *Service) Create(ctx context.Context, in task.CreateInput) (string, error) {
	in.ComponentURL = gitrepo.CanonicalRepoURL(in.ComponentURL)
	in.Branch = strings.TrimSpace(in.Branch)
	in.CVEID = strings.TrimSpace(in.CVEID)
	in.PackageName = strings.TrimSpace(in.PackageName)
	in.Model = strings.TrimSpace(in.Model)
	if in.ComponentURL == "" || in.Branch == "" || in.CVEID == "" || in.PackageName == "" {
		return "", fmt.Errorf("%w: component_url, branch, cve_id and package_name are required", task.ErrInvalidInput)
	}
	if in.Model == "" {
		in.Model = s.defaultModel
	}

	now := s.now().UTC().Format(time.RFC3339Nano)
	t := task.Task{
		ID:           uuid.NewString(),
		Status:       task.StatusPending,
		ComponentURL: in.ComponentURL,
		Branch:       in.Branch,
		CVEID:        in.CVEID,
		PackageName:  in.PackageName,
		Model:        in.Model,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.store.Create(ctx, t); err != nil {
		return "", err
	}
	if err := s.queue.Enqueue(ctx, t.ID); err != nil {
		return "", fmt.Errorf("enqueue task: %w", err)
	}
	return t.ID, nil
}

// Open returns the newest analysis with the same four fields.
// When none exists, it creates one with the default model and enqueues it.
func (s *Service) Open(ctx context.Context, in task.CreateInput) (string, error) {
	in, err := normalizeKey(in)
	if err != nil {
		return "", err
	}
	id, err := s.store.LatestID(ctx, in.ComponentURL, in.Branch, in.CVEID, in.PackageName)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, task.ErrNotFound) {
		return "", err
	}
	in.Model = ""
	return s.Create(ctx, in)
}

// Check reports the newest analysis for the four fields and does not create one.
// A missing analysis is CheckNotStarted, not an error.
func (s *Service) Check(ctx context.Context, in task.CreateInput) (string, error) {
	in, err := normalizeKey(in)
	if err != nil {
		return "", err
	}
	id, err := s.store.LatestID(ctx, in.ComponentURL, in.Branch, in.CVEID, in.PackageName)
	if errors.Is(err, task.ErrNotFound) {
		return task.CheckNotStarted, nil
	}
	if err != nil {
		return "", err
	}
	t, err := s.store.Get(ctx, id)
	if errors.Is(err, task.ErrNotFound) {
		return task.CheckNotStarted, nil
	}
	if err != nil {
		return "", err
	}
	return t.CheckResult(), nil
}

func normalizeKey(in task.CreateInput) (task.CreateInput, error) {
	in.ComponentURL = gitrepo.CanonicalRepoURL(in.ComponentURL)
	in.Branch = strings.TrimSpace(in.Branch)
	in.CVEID = strings.TrimSpace(in.CVEID)
	in.PackageName = strings.TrimSpace(in.PackageName)
	if in.ComponentURL == "" || in.Branch == "" || in.CVEID == "" || in.PackageName == "" {
		return task.CreateInput{}, fmt.Errorf("%w: component_url, branch, cve_id and package_name are required", task.ErrInvalidInput)
	}
	return in, nil
}

func (s *Service) List(ctx context.Context, f ListFilter) ([]task.Task, int, error) {
	q, err := normalizeList(f)
	if err != nil {
		return nil, 0, err
	}
	if f.Limit <= 0 {
		f.Limit = 10
	}
	if f.Limit > 100 {
		f.Limit = 100
	}
	if f.Offset < 0 {
		return nil, 0, fmt.Errorf("%w: offset must be >= 0", task.ErrInvalidInput)
	}
	items, err := s.store.List(ctx, q, f.Limit, f.Offset)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.store.Count(ctx, q)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func normalizeList(f ListFilter) (task.ListQuery, error) {
	q := task.ListQuery{
		Status:        task.Status(strings.TrimSpace(string(f.Status))),
		ComponentURL:  strings.TrimSpace(f.ComponentURL),
		Branch:        strings.TrimSpace(f.Branch),
		CVEID:         strings.TrimSpace(f.CVEID),
		PackageName:   strings.TrimSpace(f.PackageName),
		Applicability: strings.ToLower(strings.TrimSpace(f.Applicability)),
	}
	if q.Status != "" && !q.Status.Valid() {
		return task.ListQuery{}, fmt.Errorf("%w: %s", task.ErrInvalidStatus, q.Status)
	}
	switch q.Applicability {
	case "", task.Applicable, task.NotApplicable, task.Uncertain:
	default:
		return task.ListQuery{}, fmt.Errorf("%w: applicability", task.ErrInvalidInput)
	}
	return q, nil
}

const maxReviewRunes = 2000

// ReviewList is one page of analyses that have a score or a note.
// Average counts only scored analyses. A note without stars stays in Items
// and does not move Average.
type ReviewList struct {
	Items   []task.Task
	Total   int
	Rated   int
	Average *float64
}

// SetReview saves the score and the note for one analysis.
// A nil rating clears the stars. An empty note clears the text.
// Both empty removes the analysis from the review list.
func (s *Service) SetReview(ctx context.Context, id string, rating *int, text string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: id is required", task.ErrInvalidInput)
	}
	if rating != nil && (*rating < 1 || *rating > 5) {
		return fmt.Errorf("%w: rating must be from 1 to 5", task.ErrInvalidInput)
	}
	text = strings.TrimSpace(text)
	if utf8.RuneCountInString(text) > maxReviewRunes {
		return fmt.Errorf("%w: review is too long", task.ErrInvalidInput)
	}
	now := s.now().UTC().Format(time.RFC3339Nano)
	return s.store.SetReview(ctx, id, rating, text, now)
}

func (s *Service) Reviews(ctx context.Context, limit, offset int) (ReviewList, error) {
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		return ReviewList{}, fmt.Errorf("%w: offset must be >= 0", task.ErrInvalidInput)
	}
	items, err := s.store.ListReviews(ctx, limit, offset)
	if err != nil {
		return ReviewList{}, err
	}
	total, rated, sum, err := s.store.ReviewStats(ctx)
	if err != nil {
		return ReviewList{}, err
	}
	out := ReviewList{Items: items, Total: total, Rated: rated}
	if rated > 0 {
		avg := float64(sum) / float64(rated)
		out.Average = &avg
	}
	return out, nil
}

func (s *Service) Get(ctx context.Context, id string) (task.Task, error) {
	if strings.TrimSpace(id) == "" {
		return task.Task{}, fmt.Errorf("%w: id is required", task.ErrInvalidInput)
	}
	return s.store.Get(ctx, id)
}

// Cancel stops a queued or running analysis. The stored verdict is StoppedMessage.
// A finished task is left unchanged.
func (s *Service) Cancel(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: id is required", task.ErrInvalidInput)
	}
	now := s.now().UTC().Format(time.RFC3339Nano)
	ok, err := s.store.Cancel(ctx, id, task.StoppedMessage, now)
	if err != nil {
		return err
	}
	if !ok {
		if _, err := s.store.Get(ctx, id); err != nil {
			return err
		}
		return task.ErrNotCancellable
	}
	if s.queue != nil {
		if abort, ok := s.queue.(interface{ Abort(string) }); ok {
			abort.Abort(id)
		}
	}
	return nil
}

func (s *Service) Report(ctx context.Context, id string) (cveID, markdown string, err error) {
	t, err := s.Get(ctx, id)
	if err != nil {
		return "", "", err
	}
	if t.Status != task.StatusCompleted {
		return "", "", task.ErrNotCompleted
	}
	return t.CVEID, t.CombinedReport(), nil
}
