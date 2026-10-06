package model

import (
	"encoding/json"
	"net/url"
	"strings"
	"time"
)

type OperationRef struct {
	Key    string `json:"key"`
	Method string `json:"method"`
	Path   string `json:"path"`
}
type RequestRecord struct {
	RouteTemplate     string            `json:"routeTemplate"`
	ID                string            `json:"id"`
	ScanID            string            `json:"scanId"`
	SpecTitle         string            `json:"specTitle"`
	SpecVersion       string            `json:"specVersion"`
	Target            string            `json:"target"`
	Origins           []OperationRef    `json:"origins"`
	Method            string            `json:"method"`
	Path              string            `json:"path"`
	URL               string            `json:"url"`
	Strategy          string            `json:"strategy"`
	Kind              string            `json:"kind"`
	Outcome           string            `json:"outcome"`
	Reason            string            `json:"reason"`
	AuthContext       string            `json:"authContext"`
	Conditional       bool              `json:"conditional"`
	Sent              bool              `json:"sent"`
	StartedAt         time.Time         `json:"startedAt"`
	CompletedAt       time.Time         `json:"completedAt"`
	DurationMS        float64           `json:"durationMs"`
	StatusCode        int               `json:"statusCode"`
	RequestHeaders    map[string]string `json:"requestHeaders"`
	ResponseHeaders   map[string]string `json:"responseHeaders"`
	RequestBody       string            `json:"requestBody"`
	ResponseBody      string            `json:"responseBody"`
	RequestTruncated  bool              `json:"requestTruncated"`
	ResponseTruncated bool              `json:"responseTruncated"`
	SchemaResult      string            `json:"schemaResult"`
	BaselineIDs       []string          `json:"baselineIds"`
	ComparedRequestID string            `json:"comparedRequestId,omitempty"`
	FindingIDs        []string          `json:"findingIds"`
}

func TargetOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}
func SensitiveName(name string) bool {
	name = strings.ToLower(name)
	return strings.Contains(name, "authorization") || strings.Contains(name, "cookie") || strings.Contains(name, "token") || strings.Contains(name, "secret") || strings.Contains(name, "password") || strings.Contains(name, "api-key") || strings.Contains(name, "api_key") || name == "apikey"
}
func RedactHeaders(headers map[string]string, extra []string) map[string]string {
	out := map[string]string{}
	for k, v := range headers {
		redact := SensitiveName(k)
		for _, name := range extra {
			if strings.EqualFold(k, name) {
				redact = true
			}
		}
		if redact && v != "" {
			out[k] = "[redacted]"
		} else if v != "" {
			out[k] = v
		}
	}
	return out
}
func RedactBody(body string, secrets []string) string {
	for _, secret := range secrets {
		if secret != "" {
			body = strings.ReplaceAll(body, secret, "[redacted]")
		}
	}
	var value any
	if json.Unmarshal([]byte(body), &value) == nil {
		var walk func(any)
		walk = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				for k, v := range x {
					if SensitiveName(k) {
						x[k] = "[redacted]"
					} else {
						walk(v)
					}
				}
			case []any:
				for _, v := range x {
					walk(v)
				}
			}
		}
		walk(value)
		b, _ := json.Marshal(value)
		body = string(b)
	}
	return body
}
func PreviewBody(body string, limit int) (string, bool) {
	if len(body) <= limit {
		return body, false
	}
	body = body[:limit]
	for len(body) > 0 && (body[len(body)-1]&0xc0) == 0x80 {
		body = body[:len(body)-1]
	}
	return body, true
}
