package task

import (
	"errors"
	"fmt"
	"strings"
)

type Status string

const (
	StatusPending   Status = "PENDING"
	StatusRunning   Status = "RUNNING"
	StatusCompleted Status = "COMPLETED"
	StatusFailed    Status = "FAILED"
)

func (s Status) Valid() bool {
	switch s {
	case StatusPending, StatusRunning, StatusCompleted, StatusFailed:
		return true
	default:
		return false
	}
}

type Task struct {
	ID            string
	Status        Status
	ComponentURL  string
	Branch        string
	CVEID         string
	PackageName   string
	Model         string
	ErrorMsg      string
	CreatedAt     string
	UpdatedAt     string
	Applicability string
	Modules       []ModuleResult
	AICalls       int
	AIMinMS       *int64
	AIMaxMS       *int64
}

// ModuleResult is the outcome for one go.mod that lists PackageName.
// A task has one entry per such file, and none for go.mod files that do not mention the package.
type ModuleResult struct {
	GoModPath     string
	Verdict       string
	Applicability string
	ReportMD      Report
}

type CreateInput struct {
	ComponentURL string
	Branch       string
	CVEID        string
	PackageName  string
	Model        string
}

// CombinedReport joins every module report into one markdown document.
// An empty list means the scan finished and the package was not listed anywhere.
func (t Task) CombinedReport() string {
	if len(t.Modules) == 0 {
		return "Package not found in any go.mod.\n"
	}
	var b strings.Builder
	for i, m := range t.Modules {
		if i > 0 {
			b.WriteByte('\n')
		}
		if strings.TrimSpace(m.ReportMD.Narrative) != "" {
			title := m.GoModPath
			if title == "" {
				title = "module"
			}
			fmt.Fprintf(&b, "# %s\n\n%s", title, m.ReportMD.PublicText())
			continue
		}
		text := m.ReportMD.Markdown()
		b.WriteString(text)
		if !strings.HasSuffix(text, "\n") {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// StoppedMessage is the verdict written when a person stops a running analysis.
// It is not a failure of the model, Git, or the patch service.
const StoppedMessage = `Остановлен принудительно нажатием на кнопку "Остановить анализ"`

// AIMetrics counts model calls made while one analysis ran.
// MinMS and MaxMS are the fastest and slowest waits, in milliseconds.
// Both are meaningful only when Calls is greater than zero.
type AIMetrics struct {
	Calls int
	MinMS int64
	MaxMS int64
}

var (
	ErrNotFound       = errors.New("task not found")
	ErrNotCompleted   = errors.New("task is not completed")
	ErrNotCancellable = errors.New("task cannot be cancelled")
	ErrInvalidInput   = errors.New("invalid input")
	ErrInvalidStatus  = errors.New("invalid status")
)
