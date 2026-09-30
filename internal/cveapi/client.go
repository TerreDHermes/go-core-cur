package cveapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cveanalysis/internal/task"
)

// Client loads a CVE patch. A response whose message says the upstream read
// was reset is requested again until the patch arrives or ctx ends.
type Client struct {
	BaseURL    string
	HTTP       *http.Client
	RetryPause time.Duration
}

func New(baseURL string) Client {
	return Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTP:       &http.Client{Timeout: 30 * time.Second},
		RetryPause: time.Second,
	}
}

func (c Client) Fetch(ctx context.Context, cveID string) (task.CVEPatch, error) {
	if c.BaseURL == "" {
		return task.CVEPatch{}, fmt.Errorf("cve patch base url is empty")
	}
	pause := c.RetryPause
	if pause <= 0 {
		pause = time.Second
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	for {
		if err := ctx.Err(); err != nil {
			return task.CVEPatch{}, err
		}
		patch, err := c.fetchOnce(ctx, httpClient, cveID)
		if err != nil {
			if ctx.Err() != nil {
				return task.CVEPatch{}, ctx.Err()
			}
			if !strings.Contains(err.Error(), task.ConnectionResetPhrase) {
				return task.CVEPatch{}, err
			}
		} else if !patch.NeedsPatchRetry() {
			return patch, nil
		}
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
			return task.CVEPatch{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func (c Client) fetchOnce(ctx context.Context, httpClient *http.Client, cveID string) (task.CVEPatch, error) {
	endpoint := c.BaseURL + "/cve/patch/" + url.PathEscape(cveID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return task.CVEPatch{}, err
	}
	res, err := httpClient.Do(req)
	if err != nil {
		return task.CVEPatch{}, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return task.CVEPatch{}, err
	}
	var patch task.CVEPatch
	if err := json.Unmarshal(body, &patch); err != nil {
		return task.CVEPatch{}, fmt.Errorf("cve patch %s: status %d: %w", cveID, res.StatusCode, err)
	}
	if res.StatusCode != http.StatusOK && !patch.NeedsPatchRetry() {
		return task.CVEPatch{}, fmt.Errorf("cve patch %s: status %d", cveID, res.StatusCode)
	}
	return patch, nil
}
