package ai

import (
	"context"
	"sync"
	"time"
)

type callStatsKey struct{}

// CallStats collects the model calls made for one analysis.
type CallStats struct {
	mu    sync.Mutex
	calls int
	min   time.Duration
	max   time.Duration
}

func NewCallStats() *CallStats {
	return &CallStats{}
}

func WithCallStats(ctx context.Context, stats *CallStats) context.Context {
	return context.WithValue(ctx, callStatsKey{}, stats)
}

func (s *CallStats) Observe(d time.Duration) {
	if s == nil {
		return
	}
	if d < 0 {
		d = 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.calls == 1 || d < s.min {
		s.min = d
	}
	if d > s.max {
		s.max = d
	}
}

// Snapshot returns the call count and the fastest and slowest waits.
// The durations are zero when no call was recorded.
func (s *CallStats) Snapshot() (calls int, min, max time.Duration) {
	if s == nil {
		return 0, 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.min, s.max
}

func CallStatsFrom(ctx context.Context) *CallStats {
	if ctx == nil {
		return nil
	}
	stats, _ := ctx.Value(callStatsKey{}).(*CallStats)
	return stats
}

func observeCall(ctx context.Context, d time.Duration) {
	CallStatsFrom(ctx).Observe(d)
}
