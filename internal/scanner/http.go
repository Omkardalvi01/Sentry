// Package scanner implements the DAST scanning engine for zombie API detection.
package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Omkardalvi01/sentry/internal/model"
)

// HTTPClient is a tuned HTTP client for sending scan probes.
type HTTPClient struct {
	client   *http.Client
	headers  map[string]string
	maxBytes int64
}

// NewHTTPClient creates an HTTP client with a tuned transport for scanning.
func NewHTTPClient(cfg *model.ScanConfig) *HTTPClient {
	transport := &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: cfg.Timeout,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Insecure,
		},
	}

	limit := cfg.MaxResponseBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	return &HTTPClient{
		maxBytes: limit,
		client: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
			// Don't follow redirects automatically — we want to detect them
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		headers: cfg.Headers,
	}
}

// SendProbe executes a single probe and returns the result.
func (hc *HTTPClient) SendProbe(ctx context.Context, probe *model.Probe) *model.ProbeResult {
	result := &model.ProbeResult{Probe: probe}

	// Build request
	var bodyReader io.Reader
	if probe.Body != "" {
		bodyReader = strings.NewReader(probe.Body)
	}

	req, err := http.NewRequestWithContext(ctx, probe.Method, probe.URL, bodyReader)
	if err != nil {
		result.Error = fmt.Errorf("creating request: %w", err)
		return result
	}

	// Apply default headers
	req.Header.Set("User-Agent", "Sentry-DAST/0.1.0")
	req.Header.Set("Accept", "*/*")

	// Apply configured headers (e.g. auth tokens)
	for k, v := range hc.headers {
		req.Header.Set(k, v)
	}

	// Apply probe-specific headers (override defaults)
	for k, v := range probe.Headers {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}

	// Send
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()
	resp, err := hc.client.Do(req)
	result.Duration = time.Since(start)

	if err != nil {
		result.Error = fmt.Errorf("sending request: %w", err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Headers = resp.Header

	// Keep a bounded validation body; evidence is separately shortened.
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, hc.maxBytes+1))
	result.Error = readErr
	if int64(len(body)) > hc.maxBytes {
		result.Truncated = true
		body = body[:hc.maxBytes]
	}
	result.Body = string(body)

	return result
}

// NewHTTPClientWithoutAuth creates a copy of the config but strips auth-related headers.
// Used for auth bypass testing.
func NewHTTPClientWithoutAuth(cfg *model.ScanConfig) *HTTPClient {
	strippedHeaders := make(map[string]string)
	for k, v := range cfg.Headers {
		lower := strings.ToLower(k)
		// Skip auth-related headers
		if lower == "authorization" || lower == "x-api-key" ||
			lower == "x-auth-token" || lower == "cookie" {
			continue
		}
		strippedHeaders[k] = v
	}

	cfgCopy := *cfg
	cfgCopy.Headers = strippedHeaders
	return NewHTTPClient(&cfgCopy)
}
