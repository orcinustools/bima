package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

// postJSON POSTs body to url, honouring 429 rate limits (Retry-After header or
// a retry_after / parameters.retry_after JSON field) with up to 4 attempts.
func postJSON(ctx context.Context, url string, body any, headers ...string) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	backoff := time.Second
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "bima-waf/1.0")
		for i := 0; i+1 < len(headers); i += 2 {
			req.Header.Set(headers[i], headers[i+1])
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
		} else {
			rb, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			if resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("status %d: %s", resp.StatusCode, truncate(string(rb), 300))
			if resp.StatusCode == http.StatusTooManyRequests {
				if d := retryAfter(resp.Header.Get("Retry-After"), rb); d > 0 {
					backoff = d
				}
			} else if resp.StatusCode < 500 {
				return lastErr // non-retryable client error
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return lastErr
}

func retryAfter(h string, body []byte) time.Duration {
	if s, err := strconv.ParseFloat(h, 64); err == nil && s > 0 {
		return time.Duration(s * float64(time.Second))
	}
	var j struct {
		RetryAfter float64 `json:"retry_after"`
		Parameters struct {
			RetryAfter float64 `json:"retry_after"`
		} `json:"parameters"`
	}
	if json.Unmarshal(body, &j) == nil {
		if j.Parameters.RetryAfter > 0 {
			return time.Duration(j.Parameters.RetryAfter * float64(time.Second))
		}
		if j.RetryAfter > 0 {
			return time.Duration(j.RetryAfter * float64(time.Second))
		}
	}
	return 0
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
