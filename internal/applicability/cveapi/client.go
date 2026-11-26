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
// was reset, or contains 403, is requested again until the patch arrives or ctx ends.
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

// Fetch loads the patch document and decodes the fields the analysis reads.
func (c Client) Fetch(ctx context.Context, cveID string) (task.CVEPatch, error) {
	doc, err := c.fetch(ctx, cveID)
	if err != nil {
		return task.CVEPatch{}, err
	}
	return doc.patch, nil
}

// FetchDocument loads the same upstream document and keeps its status and body.
// A successful card is status 200 and the analyzer's JSON, including fields this
// service does not decode. An error status from the analyzer is returned as-is.
// Transport failures and the timeout ladder return an error and status 0.
func (c Client) FetchDocument(ctx context.Context, cveID string) (int, []byte, error) {
	doc, err := c.fetch(ctx, cveID)
	if err != nil {
		if doc.status != 0 {
			return doc.status, doc.body, nil
		}
		return 0, nil, err
	}
	return doc.status, doc.body, nil
}

type document struct {
	status int
	body   []byte
	patch  task.CVEPatch
}

func (c Client) fetch(ctx context.Context, cveID string) (document, error) {
	if c.BaseURL == "" {
		return document{}, fmt.Errorf("cve patch base url is empty")
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
			return document{}, err
		}
		limit := limits[step]
		doc, err := c.fetchAttempt(ctx, httpClient, cveID, limit)
		if err == nil && !doc.patch.NeedsPatchRetry() {
			return doc, nil
		}
		if ctx.Err() != nil {
			return document{}, ctx.Err()
		}
		switch {
		case err != nil && isAttemptTimeout(err):
			if step == len(limits)-1 {
				return document{}, fmt.Errorf("cve patch %s: request timed out after %s: %w", cveID, limit, err)
			}
			step++
		case isConnectionReset(err, doc.patch):
			step = 0
		case err != nil && doc.status != 0:
			return doc, err
		case err != nil:
			return document{}, err
		default:
			return document{}, fmt.Errorf("cve patch %s: empty response", cveID)
		}
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
			return document{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func (c Client) fetchAttempt(ctx context.Context, httpClient *http.Client, cveID string, limit time.Duration) (document, error) {
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

func (c Client) fetchOnce(ctx context.Context, httpClient *http.Client, cveID string) (document, error) {
	endpoint := c.BaseURL + "/cve/patch/" + url.PathEscape(cveID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return document{}, err
	}
	res, err := httpClient.Do(req)
	if err != nil {
		return document{}, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return document{}, err
	}
	doc := document{status: res.StatusCode, body: body}
	if err := json.Unmarshal(body, &doc.patch); err != nil {
		return doc, fmt.Errorf("cve patch %s: status %d: %w", cveID, res.StatusCode, err)
	}
	if res.StatusCode != http.StatusOK && !doc.patch.NeedsPatchRetry() {
		return doc, fmt.Errorf("cve patch %s: status %d", cveID, res.StatusCode)
	}
	return doc, nil
}
