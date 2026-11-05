package scan

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cve-patch-viewer/internal/applicability/ai"
	"cve-patch-viewer/internal/applicability/task"
)

func TestFallbackUsesQwenThenGigaChat(t *testing.T) {
	var models []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		models = append(models, modelName(body))
		switch modelName(body) {
		case "primary", reserveQwen:
			writeQueueFull(w)
		default:
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"готовый ответ"}}]}`))
		}
	}))
	defer srv.Close()

	fb := newModelFallback(ai.NewAIClient(srv.URL, "t", "env"), "primary")
	text, err := fb.Explain(context.Background(), "промпт")
	if err != nil {
		t.Fatal(err)
	}
	if text != "готовый ответ" {
		t.Fatal(text)
	}
	if strings.Join(models, ",") != "primary,"+reserveQwen+","+reserveGiga {
		t.Fatalf("%v", models)
	}
	results := []task.ModuleResult{{ReportMD: task.Report{Narrative: "журнал"}}}
	fb.stamp(results)
	if results[0].ReportMD.ActiveModel != reserveGiga {
		t.Fatal(results[0].ReportMD.ActiveModel)
	}
	text = results[0].ReportMD.PublicText()
	if !strings.Contains(text, "с primary на "+reserveQwen) || !strings.Contains(text, "на "+reserveGiga) || !strings.Contains(text, "журнал") {
		t.Fatal(text)
	}
}

func TestFallbackFromQwenGoesToGigaChat(t *testing.T) {
	var models []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		models = append(models, modelName(body))
		if modelName(body) == reserveQwen {
			writeQueueFull(w)
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer srv.Close()

	fb := newModelFallback(ai.NewAIClient(srv.URL, "t", reserveQwen), reserveQwen)
	if _, err := fb.Explain(context.Background(), "промпт"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(models, ",") != reserveQwen+","+reserveGiga {
		t.Fatalf("%v", models)
	}
	if _, err := fb.Explain(context.Background(), "ещё"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(models, ",") != reserveQwen+","+reserveGiga+","+reserveGiga {
		t.Fatalf("later call left the reserve: %v", models)
	}
}

func TestFallbackFromGigaChatDoesNotReturnToIt(t *testing.T) {
	var models []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		models = append(models, modelName(body))
		writeQueueFull(w)
	}))
	defer srv.Close()

	fb := newModelFallback(ai.NewAIClient(srv.URL, "t", reserveGiga), reserveGiga)
	_, err := fb.Explain(context.Background(), "промпт")
	if err == nil || !ai.AdmissionQueueFull(err) {
		t.Fatal(err)
	}
	if strings.Join(models, ",") != reserveGiga+","+reserveQwen {
		t.Fatalf("%v", models)
	}
}

func TestOtherRateLimitDoesNotSwitchModel(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"type":"rate_limit_error","message":"Request count limit exceeded"}}`))
	}))
	defer srv.Close()

	fb := newModelFallback(ai.NewAIClient(srv.URL, "t", "primary"), "primary")
	_, err := fb.Explain(context.Background(), "промпт")
	if err == nil || ai.AdmissionQueueFull(err) {
		t.Fatal(err)
	}
	if calls != 1 || len(fb.notes) != 0 {
		t.Fatalf("calls %d notes %v", calls, fb.notes)
	}
}

func writeQueueFull(w http.ResponseWriter) {
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte(`{"error":{"type":"rate_limit_error","code":"admission_queue_full","message":"admission queue is at capacity","param":null}}`))
}

func modelName(body []byte) string {
	const key = `"model":"`
	text := string(body)
	i := strings.Index(text, key)
	if i < 0 {
		return ""
	}
	rest := text[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	return rest[:j]
}
