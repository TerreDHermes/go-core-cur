package worker

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"cveanalysis/internal/applicability/scan"
	"cveanalysis/internal/applicability/store"
	"cveanalysis/internal/applicability/task"
)

type Cloner interface {
	Clone(ctx context.Context, url, branch string) (dir string, err error)
	Remove(dir string)
}

type Scanner interface {
	Scan(ctx context.Context, in scan.Input) ([]task.ModuleResult, error)
}

type Pool struct {
	store   store.Store
	clone   Cloner
	scan    Scanner
	ch      chan string
	workers int
	timeout time.Duration
	log     *slog.Logger
	now     func() time.Time
}

func New(st store.Store, cloner Cloner, scanner Scanner, workers, queueSize int, timeout time.Duration, log *slog.Logger) *Pool {
	if workers < 1 {
		workers = 1
	}
	if queueSize < 1 {
		queueSize = 1
	}
	if log == nil {
		log = slog.Default()
	}
	return &Pool{
		store:   st,
		clone:   cloner,
		scan:    scanner,
		ch:      make(chan string, queueSize),
		workers: workers,
		timeout: timeout,
		log:     log,
		now:     time.Now,
	}
}

func (p *Pool) Enqueue(ctx context.Context, taskID string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case p.ch <- taskID:
		return nil
	}
}

// Run requeues PENDING tasks left from the previous process, then blocks
// until ctx is cancelled and the workers finish the job they already took.
func (p *Pool) Run(ctx context.Context) error {
	ids, err := p.store.ListPendingIDs(ctx)
	if err != nil {
		return err
	}

	errCh := make(chan error, p.workers)
	for i := 0; i < p.workers; i++ {
		go func() {
			errCh <- p.loop(ctx)
		}()
	}

	for _, id := range ids {
		if err := p.Enqueue(ctx, id); err != nil {
			return err
		}
	}

	var first error
	for i := 0; i < p.workers; i++ {
		if err := <-errCh; err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (p *Pool) loop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case id := <-p.ch:
			p.handle(id)
		}
	}
}

func (p *Pool) handle(id string) {
	defer func() {
		if rec := recover(); rec != nil {
			p.fail(id, fmt.Errorf("panic: %v", rec))
		}
	}()

	log := p.log.With("task_id", id)
	claimed, err := p.store.Claim(context.Background(), id, p.stamp())
	if err != nil {
		log.Error("claim task", "err", err)
		return
	}
	if !claimed {
		log.Info("task already taken")
		return
	}
	log.Info("task running")

	t, err := p.store.Get(context.Background(), id)
	if err != nil {
		p.fail(id, err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	dir, err := p.clone.Clone(ctx, t.ComponentURL, t.Branch)
	if dir != "" {
		defer p.clone.Remove(dir)
	}
	if err != nil {
		p.fail(id, err)
		return
	}

	modules, err := p.scan.Scan(ctx, scan.Input{
		RepoPath:     dir,
		ComponentURL: t.ComponentURL,
		Branch:       t.Branch,
		CVEID:        t.CVEID,
		PackageName:  t.PackageName,
	})
	if err != nil {
		p.fail(id, err)
		return
	}
	if err := p.store.Complete(context.Background(), id, modules, p.stamp()); err != nil {
		log.Error("complete task", "err", err)
		return
	}
	log.Info("task completed", "modules", len(modules))
}

func (p *Pool) fail(id string, err error) {
	msg := err.Error()
	if len(msg) > 2000 {
		msg = msg[:2000]
	}
	p.log.Error("task failed", "task_id", id, "err", err)
	if uerr := p.store.Fail(context.Background(), id, msg, p.stamp()); uerr != nil {
		p.log.Error("record failure", "task_id", id, "err", uerr)
	}
}

func (p *Pool) stamp() string {
	return p.now().UTC().Format(time.RFC3339Nano)
}
