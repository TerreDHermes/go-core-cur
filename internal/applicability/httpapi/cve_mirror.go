package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
)

func (h *Handler) cveCard(w http.ResponseWriter, r *http.Request) {
	status, body, ok := h.loadCVE(w, r)
	if !ok {
		return
	}
	writeUpstream(w, status, body)
}

func (h *Handler) cvePatch(w http.ResponseWriter, r *http.Request) {
	status, body, ok := h.loadCVE(w, r)
	if !ok {
		return
	}
	if status != http.StatusOK {
		writeUpstream(w, status, body)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	view, found, err := patchFiles(id, body)
	if err != nil {
		writeError(w, http.StatusBadGateway, "сервис патчей вернул неразборную карточку")
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "патч для "+id+" не найден")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(view)
}

func (h *Handler) loadCVE(w http.ResponseWriter, r *http.Request) (int, []byte, bool) {
	if h.patches == nil {
		writeError(w, http.StatusInternalServerError, "сервис патчей не настроен")
		return 0, nil, false
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, "идентификатор не задан")
		return 0, nil, false
	}
	status, body, err := h.patches.FetchDocument(r.Context(), id)
	if err != nil {
		code := http.StatusBadGateway
		if strings.Contains(err.Error(), "timed out") {
			code = http.StatusGatewayTimeout
		}
		h.log.Error("cve patch lookup failed", "id", id, "err", err)
		writeError(w, code, err.Error())
		return 0, nil, false
	}
	return status, body, true
}

func writeUpstream(w http.ResponseWriter, status int, body []byte) {
	if status == 0 {
		status = http.StatusBadGateway
	}
	if len(bytes.TrimSpace(body)) == 0 {
		writeError(w, status, "сервис патчей вернул пустой ответ")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// patchFiles keeps the analyzer's file objects that actually carry a diff.
// found is false when the card has no such file.
func patchFiles(id string, body []byte) ([]byte, bool, error) {
	var doc struct {
		CVE   string            `json:"cve"`
		Files []json.RawMessage `json:"files"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false, err
	}
	var files []json.RawMessage
	for _, raw := range doc.Files {
		var file struct {
			Patch string `json:"patch"`
		}
		if err := json.Unmarshal(raw, &file); err != nil {
			return nil, false, err
		}
		if strings.TrimSpace(file.Patch) == "" {
			continue
		}
		files = append(files, raw)
	}
	if len(files) == 0 {
		return nil, false, nil
	}
	cve := doc.CVE
	if cve == "" {
		cve = id
	}
	out, err := json.Marshal(struct {
		CVE   string            `json:"cve"`
		Files []json.RawMessage `json:"files"`
	}{CVE: cve, Files: files})
	if err != nil {
		return nil, false, err
	}
	out = append(out, '\n')
	return out, true, nil
}
