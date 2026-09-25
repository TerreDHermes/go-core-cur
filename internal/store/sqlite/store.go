package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"cveanalysis/internal/task"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaFS embed.FS

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	schema, err := schemaFS.ReadFile("schema.sql")
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(string(schema)); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Create(ctx context.Context, t task.Task) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO analysis_tasks (
			id, status, component_url, branch, cve_id, package_name,
			verdict, report_md, error_msg, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)`,
		t.ID, string(t.Status), t.ComponentURL, t.Branch, t.CVEID, t.PackageName,
		t.CreatedAt, t.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert task: %w", err)
	}
	return nil
}

func (s *Store) Claim(ctx context.Context, id, updatedAt string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE analysis_tasks
		SET status = 'RUNNING', updated_at = ?
		WHERE id = ? AND status = 'PENDING'`, updatedAt, id)
	if err != nil {
		return false, fmt.Errorf("claim task: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (s *Store) Complete(ctx context.Context, id, verdict, report, updatedAt string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE analysis_tasks
		SET status = 'COMPLETED', verdict = ?, report_md = ?, error_msg = NULL, updated_at = ?
		WHERE id = ? AND status = 'RUNNING'`, verdict, report, updatedAt, id)
	if err != nil {
		return fmt.Errorf("complete task: %w", err)
	}
	return rowsOne(res, "complete")
}

func (s *Store) Fail(ctx context.Context, id, errMsg, updatedAt string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE analysis_tasks
		SET status = 'FAILED', error_msg = ?, updated_at = ?
		WHERE id = ? AND status = 'RUNNING'`, errMsg, updatedAt, id)
	if err != nil {
		return fmt.Errorf("fail task: %w", err)
	}
	return rowsOne(res, "fail")
}

func (s *Store) Get(ctx context.Context, id string) (task.Task, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, status, component_url, branch, cve_id, package_name,
		       COALESCE(verdict, ''), COALESCE(report_md, ''), COALESCE(error_msg, ''),
		       created_at, updated_at
		FROM analysis_tasks WHERE id = ?`, id)
	t, err := scanTask(row)
	if errors.Is(err, sql.ErrNoRows) {
		return task.Task{}, task.ErrNotFound
	}
	if err != nil {
		return task.Task{}, fmt.Errorf("get task: %w", err)
	}
	return t, nil
}

func (s *Store) List(ctx context.Context, status task.Status, limit, offset int) ([]task.Task, error) {
	q := `
		SELECT id, status, component_url, branch, cve_id, package_name,
		       '', '', '', created_at, updated_at
		FROM analysis_tasks`
	var args []any
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, string(status))
	}
	q += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list tasks: %w", err)
	}
	defer rows.Close()

	var out []task.Task
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if out == nil {
		out = []task.Task{}
	}
	return out, rows.Err()
}

func (s *Store) ListPendingIDs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id FROM analysis_tasks
		WHERE status = 'PENDING'
		ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("list pending: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanTask(row scanner) (task.Task, error) {
	var t task.Task
	var status string
	err := row.Scan(
		&t.ID, &status, &t.ComponentURL, &t.Branch, &t.CVEID, &t.PackageName,
		&t.Verdict, &t.ReportMD, &t.ErrorMsg, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return task.Task{}, err
	}
	t.Status = task.Status(status)
	return t, nil
}

func rowsOne(res sql.Result, op string) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("%s task: %w", op, task.ErrNotFound)
	}
	return nil
}
