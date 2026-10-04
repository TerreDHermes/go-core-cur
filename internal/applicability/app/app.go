package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sync/errgroup"

	"cveanalysis/internal/applicability/ai"
	"cveanalysis/internal/applicability/config"
	"cveanalysis/internal/applicability/cveapi"
	"cveanalysis/internal/applicability/gitrepo"
	"cveanalysis/internal/applicability/httpapi"
	"cveanalysis/internal/applicability/scan"
	"cveanalysis/internal/applicability/store/sqlite"
	"cveanalysis/internal/applicability/tasksvc"
	"cveanalysis/internal/applicability/worker"
)

func Run(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	if err := os.MkdirAll(filepath.Dir(cfg.SQLitePath), 0o755); err != nil {
		return fmt.Errorf("create sqlite dir: %w", err)
	}
	st, err := sqlite.Open(cfg.SQLitePath)
	if err != nil {
		return err
	}
	defer st.Close()

	pool := worker.New(st, gitrepo.Client{Token: cfg.GitToken}, scan.Client{
		Patches: cveapi.New(cfg.CVEPatchBase),
		AI:      ai.NewAIClient(cfg.AIBaseURL, cfg.AIToken, cfg.AIModel),
	}, cfg.WorkerCount, cfg.QueueSize, cfg.GitTimeout, log)
	svc := tasksvc.New(st, pool)

	mux := http.NewServeMux()
	httpapi.NewHandler(svc, log).Register(mux)
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return pool.Run(ctx)
	})
	g.Go(func() error {
		log.Info("http listen", "addr", cfg.HTTPAddr)
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	})
	g.Go(func() error {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	})
	return g.Wait()
}
