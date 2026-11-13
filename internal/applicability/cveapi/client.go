package cveapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cve-patch-viewer/internal/applicability/task"
)

// Client loads a CVE patch. A response whose message says the upstream read
// was reset is requested again until the patch arrives or ctx ends.
// A timed-out attempt is retried once at 50s and once at 1m. The third
// timeout stops the fetch. The shared HTTP client has no timeout of its own:
// each attempt carries its limit on the request context.
type Client struct {
	BaseURL         string
	HTTP            *http.Client
	RetryPause      time.Duration
	AttemptTimeouts []time.Duration
}

func New(baseURL string) Client {
	return Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTP:       &http.Client{},
		RetryPause: time.Second,
	}
}

func (c Client) attemptLimits() []time.Duration {
	if len(c.AttemptTimeouts) > 0 {
		return c.AttemptTimeouts
	}
	return []time.Duration{30 * time.Second, 50 * time.Second, time.Minute}
}

func (c Client) Fetch(ctx context.Context, cveID string) (task.CVEPatch, error) {
	if c.BaseURL == "" {
		return task.CVEPatch{}, fmt.Errorf("cve patch base url is empty")
	}
	pause := c.RetryPause
	if pause <= 0 {
		pause = time.Second
	}
	httpClient := clientWithoutTimeout(c.HTTP)
	limits := c.attemptLimits()
	step := 0

	for {
		if err := ctx.Err(); err != nil {
			return task.CVEPatch{}, err
		}
		limit := limits[step]
		patch, err := c.fetchAttempt(ctx, httpClient, cveID, limit)
		if err == nil && !patch.NeedsPatchRetry() {
			return patch, nil
		}
		if ctx.Err() != nil {
			return task.CVEPatch{}, ctx.Err()
		}
		switch {
		case err != nil && isAttemptTimeout(err):
			if step == len(limits)-1 {
				return task.CVEPatch{}, fmt.Errorf("cve patch %s: request timed out after %s: %w", cveID, limit, err)
			}
			step++
		case isConnectionReset(err, patch):
			step = 0
		case err != nil:
			return task.CVEPatch{}, err
		default:
			return task.CVEPatch{}, fmt.Errorf("cve patch %s: empty response", cveID)
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

func (c Client) fetchAttempt(ctx context.Context, httpClient *http.Client, cveID string, limit time.Duration) (task.CVEPatch, error) {
	attempt, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	return c.fetchOnce(attempt, httpClient, cveID)
}

func isAttemptTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var urlErr *url.Error
	return errors.As(err, &urlErr) && urlErr.Timeout()
}

func isConnectionReset(err error, patch task.CVEPatch) bool {
	if err != nil {
		return strings.Contains(err.Error(), task.ConnectionResetPhrase)
	}
	return patch.NeedsPatchRetry()
}

func clientWithoutTimeout(c *http.Client) *http.Client {
	if c == nil {
		c = http.DefaultClient
	}
	if c.Timeout == 0 {
		return c
	}
	clone := *c
	clone.Timeout = 0
	return &clone
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
