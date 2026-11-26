CREATE TABLE IF NOT EXISTS analysis_tasks (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')),
    component_url TEXT NOT NULL,
    component_key TEXT NOT NULL DEFAULT '',
    branch TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    package_name TEXT NOT NULL,
    model TEXT,
    error_msg TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    applicability TEXT,
    ai_calls INTEGER NOT NULL DEFAULT 0,
    ai_min_ms INTEGER,
    ai_max_ms INTEGER,
    clone_ms INTEGER,
    go_mod_count INTEGER,
    stop_stage TEXT,
    rating INTEGER,
    review TEXT,
    reviewed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_analysis_tasks_status_created_at
    ON analysis_tasks (status, created_at);

CREATE TABLE IF NOT EXISTS analysis_task_aliases (
    task_id TEXT NOT NULL,
    alias TEXT NOT NULL,
    PRIMARY KEY (task_id, alias),
    FOREIGN KEY (task_id) REFERENCES analysis_tasks (id)
);

CREATE INDEX IF NOT EXISTS idx_analysis_task_aliases_alias
    ON analysis_task_aliases (alias);

CREATE TABLE IF NOT EXISTS analysis_task_modules (
    task_id TEXT NOT NULL,
    go_mod_path TEXT NOT NULL,
    verdict TEXT NOT NULL,
    report_md TEXT NOT NULL,
    PRIMARY KEY (task_id, go_mod_path),
    FOREIGN KEY (task_id) REFERENCES analysis_tasks (id)
);
