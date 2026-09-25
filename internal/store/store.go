package store

import (
	"context"

	"cveanalysis/internal/task"
)

type Store interface {
	Create(ctx context.Context, t task.Task) error
	Claim(ctx context.Context, id string, updatedAt string) (bool, error)
	Complete(ctx context.Context, id, verdict, report, updatedAt string) error
	Fail(ctx context.Context, id, errMsg, updatedAt string) error
	Get(ctx context.Context, id string) (task.Task, error)
	List(ctx context.Context, status task.Status, limit, offset int) ([]task.Task, error)
	ListPendingIDs(ctx context.Context) ([]string, error)
}
