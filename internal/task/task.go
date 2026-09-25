package task

import "errors"

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
	ID           string
	Status       Status
	ComponentURL string
	Branch       string
	CVEID        string
	PackageName  string
	Verdict      string
	ReportMD     string
	ErrorMsg     string
	CreatedAt    string
	UpdatedAt    string
}

type CreateInput struct {
	ComponentURL string
	Branch       string
	CVEID        string
	PackageName  string
}

var (
	ErrNotFound      = errors.New("task not found")
	ErrNotCompleted  = errors.New("task is not completed")
	ErrInvalidInput  = errors.New("invalid input")
	ErrInvalidStatus = errors.New("invalid status")
)
