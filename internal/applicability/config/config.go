package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr     string
	SQLitePath   string
	WorkerCount  int
	GitTimeout   time.Duration
	QueueSize    int
	GitToken     string
	CVEPatchBase string
	AIBaseURL    string
	AIToken      string
	AIModel      string
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:     env("HTTP_ADDR", ":8741"),
		SQLitePath:   env("SQLITE_PATH", "data/analysis.db"),
		WorkerCount:  2,
		GitTimeout:   2 * time.Minute,
		QueueSize:    128,
		GitToken:     os.Getenv("GIT_TOKEN"),
		CVEPatchBase: env("CVE_PATCH_BASE", "http://d49.dev.k8s:8080"),
		AIBaseURL:    os.Getenv("AI_BASE_URL"),
		AIToken:      os.Getenv("AI_TOKEN"),
		AIModel:      os.Getenv("AI_MODEL"),
	}

	if v := os.Getenv("WORKER_COUNT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return Config{}, fmt.Errorf("WORKER_COUNT must be a positive integer")
		}
		cfg.WorkerCount = n
	}

	if v := os.Getenv("GIT_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return Config{}, fmt.Errorf("GIT_TIMEOUT must be a positive duration")
		}
		cfg.GitTimeout = d
	}

	if cfg.HTTPAddr == "" || cfg.SQLitePath == "" {
		return Config{}, fmt.Errorf("HTTP_ADDR and SQLITE_PATH must be set")
	}
	return cfg, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
