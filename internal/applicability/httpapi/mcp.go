package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"cve-patch-viewer/internal/applicability/task"
)

const mcpProtocol = "2025-03-26"

// mcp is the single address Gigacode talks to.
// One POST carries a JSON-RPC message. The method name says whether this is
// "list the tools" or "call this tool". The four tools use the same service
// as the site.
type mcp struct {
	h *Handler
}

func newMCP(h *Handler) mcp { return mcp{h: h} }

func (m mcp) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "mcp accepts POST", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeRPCError(w, nil, -32700, "не удалось прочитать сообщение")
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil || req.Method == "" {
		writeRPCError(w, req.ID, -32700, "сообщение не разобрано")
		return
	}
	if !req.hasID() {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	result, rpcErr := m.dispatch(r.Context(), req)
	if rpcErr != nil {
		writeRPCError(w, req.ID, rpcErr.code, rpcErr.message)
		return
	}
	writeRPCResult(w, req.ID, result)
}

type rpcRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

func (r rpcRequest) hasID() bool {
	raw := bytes.TrimSpace(r.ID)
	return len(raw) > 0 && string(raw) != "null"
}

type rpcFailure struct {
	code    int
	message string
}

func (m mcp) dispatch(ctx context.Context, req rpcRequest) (any, *rpcFailure) {
	switch req.Method {
	case "initialize":
		return m.initialize(req.Params), nil
	case "ping":
		return struct{}{}, nil
	case "tools/list":
		return map[string]any{"tools": mcpTools()}, nil
	case "tools/call":
		return m.call(ctx, req.Params)
	default:
		return nil, &rpcFailure{-32601, "неизвестный метод " + req.Method}
	}
}

func (m mcp) initialize(params json.RawMessage) map[string]any {
	version := mcpProtocol
	var body struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &body)
	if body.ProtocolVersion == "2024-11-05" || body.ProtocolVersion == mcpProtocol {
		version = body.ProtocolVersion
	}
	return map[string]any{
		"protocolVersion": version,
		"capabilities": map[string]any{
			"tools": map[string]any{"listChanged": false},
		},
		"serverInfo": map[string]any{
			"name":    "CVE Verdict",
			"version": "1.0.0",
		},
	}
}

func (m mcp) call(ctx context.Context, params json.RawMessage) (any, *rpcFailure) {
	var body struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &body); err != nil {
		return nil, &rpcFailure{-32602, "вызов инструмента не разобран"}
	}
	args := body.Arguments
	if len(bytes.TrimSpace(args)) == 0 || string(bytes.TrimSpace(args)) == "null" {
		args = []byte(`{}`)
	}
	switch body.Name {
	case "start_analysis":
		return m.startAnalysis(ctx, args), nil
	case "get_analysis":
		return m.getAnalysis(ctx, args), nil
	case "get_vulnerability":
		return m.getVulnerability(ctx, args), nil
	case "get_patch":
		return m.getPatch(ctx, args), nil
	default:
		return toolError("неизвестный инструмент " + body.Name), nil
	}
}

type fourArgs struct {
	ComponentURL string `json:"component_url"`
	Branch       string `json:"branch"`
	CVEID        string `json:"cve_id"`
	PackageName  string `json:"package_name"`
}

func (a fourArgs) input() task.CreateInput {
	return task.CreateInput{
		ComponentURL: a.ComponentURL,
		Branch:       a.Branch,
		CVEID:        a.CVEID,
		PackageName:  a.PackageName,
	}
}

func (m mcp) startAnalysis(ctx context.Context, raw json.RawMessage) any {
	var args fourArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return toolError("не разобраны четыре параметра")
	}
	id, err := m.h.svc.Create(ctx, args.input())
	if err != nil {
		return toolError(mcpServiceText(err))
	}
	return toolOK(map[string]string{
		"id":      id,
		"status":  string(task.StatusPending),
		"message": "Анализ запущен. Вердикта ещё нет: вызови get_analysis с теми же четырьмя полями.",
	})
}

func (m mcp) getAnalysis(ctx context.Context, raw json.RawMessage) any {
	var args fourArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return toolError("не разобраны четыре параметра")
	}
	found, err := m.h.svc.Find(ctx, args.input())
	if errors.Is(err, task.ErrNotFound) {
		return toolOK(map[string]string{
			"status":  "not_started",
			"result":  task.CheckNotStarted,
			"message": "Такого анализа нет.",
		})
	}
	if err != nil {
		return toolError(mcpServiceText(err))
	}
	out := map[string]any{
		"id":      found.ID,
		"status":  string(found.Status),
		"result":  found.CheckResult(),
		"message": analysisMessage(found),
	}
	if found.Status == task.StatusCompleted {
		out["applicability"] = found.PublicApplicability()
	}
	if msg := strings.TrimSpace(found.ErrorMsg); msg != "" {
		out["error"] = msg
	}
	modules := make([]map[string]string, 0, len(found.Modules))
	for _, module := range found.Modules {
		kind := module.Applicability
		if kind == "" {
			kind = module.ReportMD.Applicability
		}
		modules = append(modules, map[string]string{
			"go_mod_path":   module.GoModPath,
			"verdict":       module.Verdict,
			"applicability": kind,
		})
	}
	if len(modules) > 0 {
		out["modules"] = modules
	}
	if files := task.VisiblePatchFiles(found.Modules); len(files) > 0 {
		out["patch_files"] = files
	}
	return toolOK(out)
}

func analysisMessage(t task.Task) string {
	switch t.CheckResult() {
	case task.CheckInProgress:
		return "Анализ ещё идёт, вердикта нет."
	case task.CheckFailed:
		return "Анализ закончился ошибкой."
	case task.Applicable:
		return "Уязвимость применима."
	case task.NotApplicable:
		return "Уязвимость неприменима."
	case task.Uncertain:
		return "Вывод неопределённый."
	default:
		return "Анализ найден."
	}
}

func (m mcp) getVulnerability(ctx context.Context, raw json.RawMessage) any {
	id, bad := vulnerabilityID(raw)
	if bad != nil {
		return bad
	}
	if m.h.patches == nil {
		return toolError("сервис патчей не настроен")
	}
	status, body, err := m.h.patches.FetchDocument(ctx, id)
	if err != nil {
		return toolError(err.Error())
	}
	if status != http.StatusOK {
		return toolError(upstreamText(id, status, body))
	}
	return toolOK(json.RawMessage(body))
}

func (m mcp) getPatch(ctx context.Context, raw json.RawMessage) any {
	id, bad := vulnerabilityID(raw)
	if bad != nil {
		return bad
	}
	if m.h.patches == nil {
		return toolError("сервис патчей не настроен")
	}
	status, body, err := m.h.patches.FetchDocument(ctx, id)
	if err != nil {
		return toolError(err.Error())
	}
	if status != http.StatusOK {
		return toolError(upstreamText(id, status, body))
	}
	view, found, err := patchFiles(id, body)
	if err != nil {
		return toolError("сервис патчей вернул неразборную карточку")
	}
	if !found {
		return toolOK(map[string]any{
			"found":   false,
			"id":      id,
			"message": "патч для " + id + " не найден",
		})
	}
	return toolOK(json.RawMessage(bytes.TrimSpace(view)))
}

func vulnerabilityID(raw json.RawMessage) (string, any) {
	var args struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return "", toolError("не разобран идентификатор")
	}
	id := strings.TrimSpace(args.ID)
	if id == "" || strings.Contains(id, "/") {
		return "", toolError("идентификатор не задан")
	}
	return id, nil
}

func upstreamText(id string, status int, body []byte) string {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return "сервис патчей ответил " + http.StatusText(status) + " для " + id
	}
	return text
}

func mcpServiceText(err error) string {
	if errors.Is(err, task.ErrInvalidInput) {
		return "Нужны адрес репозитория, ветка, идентификатор уязвимости и имя пакета."
	}
	return err.Error()
}

type toolPayload struct {
	Content []toolText `json:"content"`
	IsError bool       `json:"isError,omitempty"`
}

type toolText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func toolOK(value any) toolPayload {
	return toolPayload{Content: []toolText{{Type: "text", Text: toolJSON(value)}}}
}

func toolError(message string) toolPayload {
	return toolPayload{
		IsError: true,
		Content: []toolText{{Type: "text", Text: message}},
	}
}

func toolJSON(value any) string {
	if raw, ok := value.(json.RawMessage); ok {
		var pretty bytes.Buffer
		if json.Indent(&pretty, raw, "", "  ") == nil {
			return pretty.String()
		}
		return string(raw)
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(raw)
}

func mcpTools() []map[string]any {
	four := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"component_url": map[string]string{"type": "string", "description": "Адрес репозитория: https, ssh или git@."},
			"branch":        map[string]string{"type": "string", "description": "Ветка, точно как в репозитории."},
			"cve_id":        map[string]string{"type": "string", "description": "CVE, GO- или GHSA."},
			"package_name":  map[string]string{"type": "string", "description": "Имя пакета, root или stdlib."},
		},
		"required": []string{"component_url", "branch", "cve_id", "package_name"},
	}
	one := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"id": map[string]string{"type": "string", "description": "Идентификатор уязвимости: CVE, GO- или GHSA."},
		},
		"required": []string{"id"},
	}
	return []map[string]any{
		{
			"name":        "start_analysis",
			"description": "Запускает новый анализ применимости уязвимости к репозиторию. Ответ приходит сразу, с id задачи. Вердикт ещё не готов: его забирает get_analysis с теми же четырьмя полями. Повторный вызов создаёт ещё один анализ.",
			"inputSchema": four,
		},
		{
			"name":        "get_analysis",
			"description": "Возвращает самый новый анализ применимости по адресу репозитория, ветке, идентификатору уязвимости и пакету. Ничего не создаёт. Разные написания адреса считаются одним репозиторием. Пока карточка патча не сохранена, узнаётся только id запуска. Если анализ ещё идёт, вердикта нет.",
			"inputSchema": four,
		},
		{
			"name":        "get_vulnerability",
			"description": "Карточка уязвимости по CVE, GO- или GHSA: описание, алиасы и ссылки. Анализ применимости не создаёт.",
			"inputSchema": one,
		},
		{
			"name":        "get_patch",
			"description": "Патч уязвимости по CVE, GO- или GHSA: файлы, в которых есть текст diff. Если diff нет, сообщает, что патч не найден. Анализ применимости не создаёт.",
			"inputSchema": one,
		},
	}
}

func writeRPCResult(w http.ResponseWriter, id json.RawMessage, result any) {
	writeRPC(w, map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"result":  result,
	})
}

func writeRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
	if !(rpcRequest{ID: id}).hasID() {
		id = []byte("null")
	}
	writeRPC(w, map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(id),
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}

func writeRPC(w http.ResponseWriter, payload map[string]any) {
	raw, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "mcp response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
