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

// Explain is the scan-facing name for CallAI.
func (c *AIClient) Explain(ctx context.Context, prompt string) (string, error) {
	return c.CallAI(ctx, prompt)
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
