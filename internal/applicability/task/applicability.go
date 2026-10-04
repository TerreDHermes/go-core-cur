package task

import (
	"strings"
	"time"
)

const (
	Applicable    = "applicable"
	NotApplicable = "not_applicable"
	Uncertain     = "uncertain"
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

// DurationMS is updated_at minus created_at, in milliseconds.
// That is how long the task has been open from the client's request until the last status change.
func (t Task) DurationMS() *int64 {
	created, okCreated := parseStamp(t.CreatedAt)
	updated, okUpdated := parseStamp(t.UpdatedAt)
	if !okCreated || !okUpdated {
		return nil
	}
	if updated.Before(created) {
		zero := int64(0)
		return &zero
	}
	ms := updated.Sub(created).Milliseconds()
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
