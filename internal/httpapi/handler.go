package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"cveanalysis/internal/task"
	"cveanalysis/internal/tasksvc"
)

type Service interface {
	Create(ctx context.Context, in task.CreateInput) (string, error)
	List(ctx context.Context, f tasksvc.ListFilter) ([]task.Task, error)
	Get(ctx context.Context, id string) (task.Task, error)
	Report(ctx context.Context, id string) (cveID, markdown string, err error)
}

type Handler struct {
	svc Service
	log *slog.Logger
}

func NewHandler(svc Service, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{svc: svc, log: log}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/analysis", h.create)
	mux.HandleFunc("GET /api/v1/analysis", h.list)
	mux.HandleFunc("GET /api/v1/analysis/{id}", h.get)
	mux.HandleFunc("GET /api/v1/analysis/{id}/report", h.report)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ComponentURL string `json:"component_url"`
		Branch       string `json:"branch"`
		CVEID        string `json:"cve_id"`
		PackageName  string `json:"package_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	id, err := h.svc.Create(r.Context(), task.CreateInput{
		ComponentURL: body.ComponentURL,
		Branch:       body.Branch,
		CVEID:        body.CVEID,
		PackageName:  body.PackageName,
	})
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id})
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 10
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "limit must be an integer")
			return
		}
		limit = n
	}
	offset := 0
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "offset must be an integer")
			return
		}
		offset = n
	}
	items, err := h.svc.List(r.Context(), tasksvc.ListFilter{
		Status: task.Status(q.Get("status")),
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	out := make([]map[string]string, 0, len(items))
	for _, t := range items {
		out = append(out, map[string]string{
			"id":            t.ID,
			"status":        string(t.Status),
			"cve_id":        t.CVEID,
			"component_url": t.ComponentURL,
			"branch":        t.Branch,
			"package_name":  t.PackageName,
			"created_at":    t.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	t, err := h.svc.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	modules := make([]moduleResponse, 0, len(t.Modules))
	for _, m := range t.Modules {
		modules = append(modules, moduleResponse{
			GoModPath: m.GoModPath,
			Verdict:   m.Verdict,
			ReportMD:  m.ReportMD.PublicText(),
		})
	}
	writeJSON(w, http.StatusOK, taskResponse{
		ID:           t.ID,
		Status:       string(t.Status),
		ComponentURL: t.ComponentURL,
		Branch:       t.Branch,
		CVEID:        t.CVEID,
		PackageName:  t.PackageName,
		Modules:      modules,
		ErrorMsg:     t.ErrorMsg,
		CreatedAt:    t.CreatedAt,
		UpdatedAt:    t.UpdatedAt,
	})
}

type taskResponse struct {
	ID           string           `json:"id"`
	Status       string           `json:"status"`
	ComponentURL string           `json:"component_url"`
	Branch       string           `json:"branch"`
	CVEID        string           `json:"cve_id"`
	PackageName  string           `json:"package_name"`
	Modules      []moduleResponse `json:"modules"`
	ErrorMsg     string           `json:"error_msg"`
	CreatedAt    string           `json:"created_at"`
	UpdatedAt    string           `json:"updated_at"`
}

type moduleResponse struct {
	GoModPath string `json:"go_mod_path"`
	Verdict   string `json:"verdict"`
	ReportMD  string `json:"report_md"`
}

func (h *Handler) report(w http.ResponseWriter, r *http.Request) {
	cveID, markdown, err := h.svc.Report(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err)
		return
	}
	filename := sanitizeFilename(cveID)
	w.Header().Set("Content-Type", "text/markdown")
	w.Header().Set("Content-Disposition", `attachment; filename="report-`+filename+`.md"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(markdown))
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, task.ErrInvalidInput), errors.Is(err, task.ErrInvalidStatus):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, task.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, task.ErrNotCompleted):
		writeError(w, http.StatusConflict, err.Error())
	default:
		h.log.Error("request failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func sanitizeFilename(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		default:
			return '_'
		}
	}, s)
	if s == "" {
		return "report"
	}
	return s
}
