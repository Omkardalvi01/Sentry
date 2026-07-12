package model

import "time"

// TrafficEvent represents an API request and response captured from the gateway.
type TrafficEvent struct {
	RequestID       string            `json:"request_id"`
	Method          string            `json:"method"`
	Path            string            `json:"path"`
	QueryParams     string            `json:"query_params"`
	RequestHeaders  map[string]string `json:"request_headers"`
	RequestBody     string            `json:"request_body"`
	StatusCode      int               `json:"status_code"`
	ResponseHeaders map[string]string `json:"response_headers"`
	ResponseBody    string            `json:"response_body"`
	Timestamp       time.Time         `json:"timestamp"`
}
