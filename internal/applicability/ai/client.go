package ai

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// AIClient calls an OpenAI-compatible chat endpoint.
// Certificate verification is off: this contour presents a private certificate.
type AIClient struct {
	BaseURL   string
	AuthToken string
	Model     string
	Client    *http.Client
}

func NewAIClient(baseURL, token, model string) *AIClient {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &AIClient{
		BaseURL:   strings.TrimSuffix(baseURL, "/"),
		AuthToken: token,
		Model:     model,
		Client: &http.Client{
			Transport: tr,
		},
	}
}

// CallAI posts one user prompt and returns the assistant text.
func (c *AIClient) CallAI(ctx context.Context, prompt string) (string, error) {
	if prompt == "" {
		return "", nil
	}
	if c.BaseURL == "" {
		return "", fmt.Errorf("ai base url is empty")
	}
	requestBody := AIRequestBody{
		Messages: []AIRequestMessage{{
			Role:    "user",
			Content: prompt,
		}},
		Model: c.Model,
	}
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal AI request body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", fmt.Errorf("create AI request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	req.Header.Set("Content-Type", "application/json")

	httpClient := c.Client
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("do AI request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("AI API returned %d: %s", resp.StatusCode, string(bodyBytes))
	}
	var aiResp AIResponse
	if err := json.NewDecoder(resp.Body).Decode(&aiResp); err != nil {
		return "", fmt.Errorf("decode AI response: %w", err)
	}
	if len(aiResp.Choices) == 0 || aiResp.Choices[0].Message.Content == "" {
		return "", fmt.Errorf("AI response has no content")
	}
	return aiResp.Choices[0].Message.Content, nil
}

// WithModel returns a copy that calls the given model. The original client stays on its own model,
// so parallel tasks can use different models.
func (c *AIClient) WithModel(model string) *AIClient {
	if c == nil {
		return nil
	}
	next := *c
	if name := strings.TrimSpace(model); name != "" {
		next.Model = name
	}
	return &next
}

// Explain is the scan-facing name for CallAI.
func (c *AIClient) Explain(ctx context.Context, prompt string) (string, error) {
	return c.CallAI(ctx, prompt)
}

// ModelsURL is the OpenAI-compatible model list for a chat URL.
// https://host/v1/chat/completions becomes https://host/v1/models.
func ModelsURL(chatURL string) string {
	u := strings.TrimRight(strings.TrimSpace(chatURL), "/")
	switch {
	case strings.HasSuffix(u, "/chat/completions"):
		return strings.TrimSuffix(u, "/chat/completions") + "/models"
	case strings.HasSuffix(u, "/completions"):
		return strings.TrimSuffix(u, "/completions") + "/models"
	default:
		return u + "/models"
	}
}

// ListModels calls GET /models with the same token as chat completions.
func (c *AIClient) ListModels(ctx context.Context) ([]string, error) {
	if c == nil || c.BaseURL == "" {
		return nil, fmt.Errorf("ai base url is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ModelsURL(c.BaseURL), nil)
	if err != nil {
		return nil, fmt.Errorf("create models request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.AuthToken)

	httpClient := c.Client
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do models request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read models response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("models API returned %d: %s", resp.StatusCode, trimBody(body))
	}
	var parsed struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode models response: %w", err)
	}
	names := make([]string, 0, len(parsed.Data))
	seen := map[string]bool{}
	for _, item := range parsed.Data {
		name := strings.TrimSpace(item.ID)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names, nil
}

func trimBody(body []byte) string {
	text := strings.TrimSpace(string(body))
	if len(text) > 300 {
		return text[:300]
	}
	return text
}

type AIRequestMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type AIRequestBody struct {
	Messages []AIRequestMessage `json:"messages"`
	Model    string             `json:"model"`
}

type AIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}
