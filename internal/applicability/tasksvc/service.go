package tasksvc

import (
	"context"
	"fmt"
	"strings"
	"time"

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
	Status task.Status
	Limit  int
	Offset int
}

func (s *Service) Create(ctx context.Context, in task.CreateInput) (string, error) {
	in.ComponentURL = strings.TrimSpace(in.ComponentURL)
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

func (s *Service) List(ctx context.Context, f ListFilter) ([]task.Task, int, error) {
	if f.Status != "" && !f.Status.Valid() {
		return nil, 0, fmt.Errorf("%w: %s", task.ErrInvalidStatus, f.Status)
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
	items, err := s.store.List(ctx, f.Status, f.Limit, f.Offset)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.store.Count(ctx, f.Status)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (s *Service) Get(ctx context.Context, id string) (task.Task, error) {
	if strings.TrimSpace(id) == "" {
		return task.Task{}, fmt.Errorf("%w: id is required", task.ErrInvalidInput)
	}
	return s.store.Get(ctx, id)
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
