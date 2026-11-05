package task

import (
	"strings"
	"time"
)

const (
	Applicable    = "applicable"
	NotApplicable = "not_applicable"
	Uncertain     = "uncertain"

	// Check results for the dashboard status button. The three verdicts reuse
	// the applicability values. The other three describe a task that has no verdict yet.
	CheckNotStarted = "not_started"
	CheckInProgress = "in_progress"
	CheckFailed     = "failed"
)

// ClassifyVerdict reads a verdict paragraph. "неприменима" is checked as its own word,
// so it is not mistaken for "применима". Text that picks neither side is uncertain.
func ClassifyVerdict(text string) string {
	lower := strings.ToLower(text)
	bestAt := -1
	best := ""
	consider := func(at int, kind string) {
		if at < 0 {
			return
		}
		if bestAt < 0 || at < bestAt {
			bestAt = at
			best = kind
		}
	}
	consider(strings.Index(lower, "неприменима"), NotApplicable)
	consider(strings.Index(lower, "не применима"), NotApplicable)
	consider(strings.Index(lower, "не оценен"), Uncertain)
	consider(strings.Index(lower, "неопредел"), Uncertain)
	rest := lower
	offset := 0
	for {
		i := strings.Index(rest, "применима")
		if i < 0 {
			break
		}
		abs := offset + i
		if abs < 2 || lower[abs-2:abs] != "не" {
			consider(abs, Applicable)
			break
		}
		next := i + len("применима")
		offset += next
		rest = rest[next:]
	}
	if best == "" {
		return Uncertain
	}
	return best
}

// RollupApplicability combines module results into one task value.
// Any applicable module makes the task applicable. Otherwise an uncertain
// module keeps the task uncertain. The task is not applicable only when every module is not applicable.
func RollupApplicability(modules []ModuleResult) string {
	if len(modules) == 0 {
		return Uncertain
	}
	sawNot := false
	sawUncertain := false
	for _, m := range modules {
		switch m.Applicability {
		case Applicable:
			return Applicable
		case NotApplicable:
			sawNot = true
		default:
			sawUncertain = true
		}
	}
	if sawUncertain || !sawNot {
		return Uncertain
	}
	return NotApplicable
}

// CheckResult is the single answer for the dashboard status button.
// A missing task is reported by the caller as CheckNotStarted.
// A failed task stays failed even though its stored applicability is uncertain.
func (t Task) CheckResult() string {
	switch t.Status {
	case StatusPending, StatusRunning:
		return CheckInProgress
	case StatusFailed:
		return CheckFailed
	case StatusCompleted:
		kind := t.Applicability
		if kind == "" {
			kind = RollupApplicability(t.Modules)
		}
		switch kind {
		case Applicable, NotApplicable, Uncertain:
			return kind
		default:
			return Uncertain
		}
	default:
		return CheckInProgress
	}
}

// PublicApplicability is the task-level value for the API.
// A task that has not finished yet has no value. A failed task is uncertain.
func (t Task) PublicApplicability() *string {
	kind := t.Applicability
	switch {
	case kind != "":
	case t.Status == StatusFailed:
		kind = Uncertain
	case t.Status == StatusCompleted:
		kind = RollupApplicability(t.Modules)
	default:
		return nil
	}
	return &kind
}

// DurationMS is how long the analysis itself has been running, in milliseconds.
// The clock starts when a worker claims the task. A queued task has no duration.
// A running task is measured up to now. A finished task ends at updated_at.
// Rows saved before started_at existed fall back to updated_at minus created_at.
func (t Task) DurationMS(now time.Time) *int64 {
	start, okStart := parseStamp(t.StartedAt)
	switch t.Status {
	case StatusPending:
		return nil
	case StatusRunning:
		if !okStart {
			return nil
		}
		return diffMS(start, now)
	default:
		end, okEnd := parseStamp(t.UpdatedAt)
		if !okStart {
			start, okStart = parseStamp(t.CreatedAt)
		}
		if !okStart || !okEnd {
			return nil
		}
		return diffMS(start, end)
	}
}

func diffMS(start, end time.Time) *int64 {
	if end.Before(start) {
		zero := int64(0)
		return &zero
	}
	ms := end.Sub(start).Milliseconds()
	return &ms
}

func parseStamp(v string) (time.Time, bool) {
	if strings.TrimSpace(v) == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}
