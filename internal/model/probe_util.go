package model

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// pathParamRegex matches path parameters like {id}, {petId}, etc.
var pathParamRegex = regexp.MustCompile(`\{([^}]+)\}`)

// BuildURL constructs a full URL from a base target URL and a path template.
// Path parameters (e.g. {id}) are replaced with dummy values.
func BuildURL(target, pathTemplate string) string {
	target = strings.TrimRight(target, "/")

	// Replace path parameters with dummy values
	resolved := pathParamRegex.ReplaceAllStringFunc(pathTemplate, func(match string) string {
		paramName := strings.Trim(match, "{}")
		return dummyValue(paramName)
	})

	return target + resolved
}

// dummyValue generates a safe dummy value for a path parameter based on its name.
func dummyValue(paramName string) string {
	lower := strings.ToLower(paramName)
	switch {
	case strings.Contains(lower, "id"):
		return "1"
	case strings.Contains(lower, "name"):
		return "test"
	case strings.Contains(lower, "slug"):
		return "test-slug"
	case strings.Contains(lower, "uuid"):
		return "00000000-0000-0000-0000-000000000000"
	case strings.Contains(lower, "email"):
		return "test@example.com"
	case strings.Contains(lower, "date"):
		return "2024-01-01"
	default:
		return "test"
	}
}

// MakeProbe is a convenience function to create a probe.
func MakeProbe(target, path, method, strategy string, meta map[string]string) *Probe {
	return &Probe{
		URL:      BuildURL(target, path),
		Path:     path,
		Method:   method,
		Strategy: strategy,
		Headers:  make(map[string]string),
		Meta:     meta,
	}
}

// FormatEvidence creates a JSON-ish evidence string from a probe result.
func FormatEvidence(result *ProbeResult) string {
	if result.Error != nil {
		return fmt.Sprintf(`{"error": %q}`, result.Error.Error())
	}

	// Collect interesting headers
	interestingHeaders := []string{
		"Content-Type", "Server", "X-Powered-By", "X-Request-Id",
		"WWW-Authenticate", "Allow",
	}
	var headerParts []string
	for _, h := range interestingHeaders {
		if vals, ok := result.Headers[h]; ok && len(vals) > 0 {
			headerParts = append(headerParts, fmt.Sprintf("%q: %q", h, vals[0]))
		}
	}

	bodySnippet := result.Body
	if len(bodySnippet) > 200 {
		bodySnippet = bodySnippet[:200] + "..."
	}

	return fmt.Sprintf(`{"statusCode": %d, "headers": {%s}, "bodySnippet": %q, "duration": %q}`,
		result.StatusCode,
		strings.Join(headerParts, ", "),
		bodySnippet,
		result.Duration.Round(time.Millisecond),
	)
}
