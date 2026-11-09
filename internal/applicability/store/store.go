package store

import (
	"context"

	"cve-patch-viewer/internal/applicability/task"
)

type Store interface {
	Create(ctx context.Context, t task.Task) error
	Claim(ctx context.Context, id string, updatedAt string) (bool, error)
	Complete(ctx context.Context, id string, modules []task.ModuleResult, updatedAt string) error
	Fail(ctx context.Context, id, errMsg, updatedAt string) error
	Cancel(ctx context.Context, id, errMsg, updatedAt string) (bool, error)
	SaveAIMetrics(ctx context.Context, id string, m task.AIMetrics) error
	SaveCloneMS(ctx context.Context, id string, ms int64) error
	SetModel(ctx context.Context, id, model string) error
	RequeueRunning(ctx context.Context, updatedAt string) ([]string, error)
	Get(ctx context.Context, id string) (task.Task, error)
	LatestID(ctx context.Context, componentURL, branch, cveID, packageName string) (string, error)
	List(ctx context.Context, status task.Status, limit, offset int) ([]task.Task, error)
	Count(ctx context.Context, status task.Status) (int, error)
	ListPendingIDs(ctx context.Context) ([]string, error)
}
