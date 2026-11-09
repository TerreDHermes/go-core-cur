package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"cve-patch-viewer/internal/applicability/ai"
	"cve-patch-viewer/internal/applicability/scan"
	"cve-patch-viewer/internal/applicability/store"
	"cve-patch-viewer/internal/applicability/task"
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
	cancels sync.Map
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

// Abort stops the analysis this process is running for id.
// A task that is only queued has no cancel function; its row is already failed.
func (p *Pool) Abort(id string) {
	if p == nil {
		return
	}
	v, ok := p.cancels.Load(id)
	if !ok {
		return
	}
	v.(context.CancelFunc)()
}

// Run puts interrupted RUNNING tasks back on the queue, then the PENDING ones,
// and blocks until ctx is cancelled and the workers finish the job they already took.
func (p *Pool) Run(ctx context.Context) error {
	running, err := p.store.RequeueRunning(ctx, p.stamp())
	if err != nil {
		return err
	}
	if len(running) > 0 {
		p.log.Info("requeue interrupted tasks", "count", len(running))
	}
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
	var stats *ai.CallStats
	defer func() {
		if rec := recover(); rec != nil {
			p.persistAI(id, stats)
			p.fail(id, fmt.Errorf("panic: %v", rec))
			return
		}
		// A deadline can leave the task failed after the last model call.
		// Saving here keeps that call on the page even when finish already returned.
		p.persistAI(id, stats)
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
	stats = ai.NewCallStats()

	t, err := p.store.Get(context.Background(), id)
	if err != nil {
		p.finish(id, nil, stats, err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	ctx = ai.WithCallStats(ctx, stats)
	p.cancels.Store(id, cancel)
	defer func() {
		cancel()
		p.cancels.Delete(id)
	}()

	// The deadline can fire while git or deadcode is still exiting.
	// Write the calls we already have so the page is not left blank.
	stopStats := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			p.persistAI(id, stats)
		case <-stopStats:
		}
	}()
	defer close(stopStats)

	cloneStarted := time.Now()
	dir, err := p.clone.Clone(ctx, t.ComponentURL, t.Branch)
	p.persistClone(id, time.Since(cloneStarted))
	if dir != "" {
		defer p.clone.Remove(dir)
	}
	if err != nil {
		p.finish(id, nil, stats, err)
		return
	}

	modules, err := p.scan.Scan(ctx, scan.Input{
		RepoPath:     dir,
		ComponentURL: t.ComponentURL,
		Branch:       t.Branch,
		CVEID:        t.CVEID,
		PackageName:  t.PackageName,
		Model:        t.Model,
	})
	if err == nil {
		if model := switchedModel(modules); model != "" && model != t.Model {
			if uerr := p.store.SetModel(context.Background(), id, model); uerr != nil {
				log.Error("save model", "err", uerr)
			} else {
				log.Info("model switched", "from", t.Model, "to", model)
			}
		}
	}
	p.finish(id, modules, stats, err)
}

func switchedModel(modules []task.ModuleResult) string {
	for _, m := range modules {
		if model := strings.TrimSpace(m.ReportMD.ActiveModel); model != "" {
			return model
		}
	}
	return ""
}

func (p *Pool) finish(id string, modules []task.ModuleResult, stats *ai.CallStats, err error) {
	p.persistAI(id, stats)
	if err != nil {
		p.fail(id, err)
		return
	}
	if err := p.store.Complete(context.Background(), id, modules, p.stamp()); err != nil {
		if errors.Is(err, task.ErrNotFound) {
			p.log.Info("task already finished", "task_id", id)
			return
		}
		p.log.Error("complete task", "task_id", id, "err", err)
		return
	}
	p.log.Info("task completed", "task_id", id, "modules", len(modules))
}

func (p *Pool) persistAI(id string, stats *ai.CallStats) {
	if stats == nil {
		return
	}
	calls, min, max := stats.Snapshot()
	m := task.AIMetrics{Calls: calls}
	if calls > 0 {
		m.MinMS = min.Milliseconds()
		m.MaxMS = max.Milliseconds()
	}
	if err := p.store.SaveAIMetrics(context.Background(), id, m); err != nil {
		p.log.Error("save ai metrics", "task_id", id, "err", err)
	}
}

func (p *Pool) persistClone(id string, d time.Duration) {
	ms := d.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	if err := p.store.SaveCloneMS(context.Background(), id, ms); err != nil {
		p.log.Error("save clone time", "task_id", id, "err", err)
	}
}

func (p *Pool) fail(id string, err error) {
	msg := err.Error()
	if len(msg) > 2000 {
		msg = msg[:2000]
	}
	if uerr := p.store.Fail(context.Background(), id, msg, p.stamp()); uerr != nil {
		if errors.Is(uerr, task.ErrNotFound) {
			p.log.Info("task already finished", "task_id", id)
			return
		}
		p.log.Error("record failure", "task_id", id, "err", uerr)
		return
	}
	p.log.Error("task failed", "task_id", id, "err", err)
}

func (p *Pool) stamp() string {
	return p.now().UTC().Format(time.RFC3339Nano)
}
