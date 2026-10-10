package model

import "time"

// TrafficEvent represents an API request and response captured from the gateway.
type TrafficEvent struct {
	TargetOrigin      string            `json:"target_origin"`
	RequestID         string            `json:"request_id"`
	Method            string            `json:"method"`
	Path              string            `json:"path"`
	QueryParams       string            `json:"query_params"`
	RequestHeaders    map[string]string `json:"request_headers"`
	RequestBody       string            `json:"request_body"`
	StatusCode        int               `json:"status_code"`
	ResponseHeaders   map[string]string `json:"response_headers"`
	ResponseBody      string            `json:"response_body"`
	ResponseTimeMS    float64           `json:"response_time_ms,omitempty"`
	ResponseSizeBytes int64             `json:"response_size_bytes,omitempty"`
	Timestamp         time.Time         `json:"timestamp"`

	SpecTitle          string `json:"spec_title"`
	SpecVersion        string `json:"spec_version"`
	GraphKnown         *bool  `json:"graph_known"`
	GraphContextStatus string `json:"graph_context_status"`
	TrainingEligible   bool   `json:"training_eligible"`

	// Inventory features
	GraphPathTemplate    string `json:"graph_path_template"`
	GraphDeprecated      bool   `json:"graph_deprecated"`
	GraphSecurity        string `json:"graph_security"`
	GraphTag             string `json:"graph_tag"`
	GraphDependencyCount int    `json:"graph_dependency_count"`
}
