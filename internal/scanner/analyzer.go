package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Omkardalvi01/sentry/internal/graph"
	"github.com/Omkardalvi01/sentry/internal/model"
)

// Analyze evaluates a ProbeResult and returns a Finding if a zombie was detected.
// Returns nil if the result is not interesting.
func Analyze(ctx context.Context, result *model.ProbeResult, baseline *model.ProbeResult, graphClient *graph.Client) *model.Finding {
	if result.Error != nil {
		return nil // Connection failed — endpoint not reachable
	}

	probe := result.Probe
	var finding *model.Finding

	switch probe.Strategy {
	case model.StrategyDeprecatedAlive:
		finding = analyzeDeprecatedAlive(result, baseline)
	case model.StrategyVersionProbe:
		finding = analyzeVersionProbe(result, baseline)
	case model.StrategyMethodProbe:
		finding = analyzeMethodProbe(result, baseline)
	case model.StrategyShadowPath:
		finding = analyzeShadowPath(result, baseline)
	case model.StrategyAuthBypass:
		finding = analyzeAuthBypass(result, baseline)
	}

	if finding != nil && graphClient != nil {
		// Calculate Blast Radius
		gc, err := graphClient.ResolveTrafficContext(ctx, finding.Method, finding.Path)
		if err == nil && gc.DependencyCount > 0 {
			// Upgrade severity based on blast radius
			if finding.Severity == model.SeverityLow || finding.Severity == model.SeverityMedium {
				finding.Severity = model.SeverityHigh
			}
			finding.Description += fmt.Sprintf(" (Graph-Calculated Blast Radius: High! Traversed %d downstream dependencies)", gc.DependencyCount)
		}
	}

	return finding
}

func analyzeDeprecatedAlive(r *model.ProbeResult, baseline *model.ProbeResult) *model.Finding {
	if r.StatusCode >= 200 && r.StatusCode < 400 {
		if isCatchAll(r, baseline) {
			return nil // False positive: Catch-all route
		}

		severity := model.SeverityCritical
		desc := "This endpoint is marked as deprecated in the API specification but is still responding to requests, and its response matches the expected schema. This is a Confirmed Zombie API."
		
		schemaStr := r.Probe.Meta["responses_schema"]
		contentType := ""
		if ctVals, ok := r.Headers["Content-Type"]; ok && len(ctVals) > 0 {
			contentType = ctVals[0]
		}
		
		valid, _ := ValidateSchema(schemaStr, r.StatusCode, contentType, r.Body)
		if !valid {
			if hasRetirementKeywords(r.Body) {
				return nil // False positive: Gracefully retired
			}
			severity = model.SeverityMedium
			desc = "This endpoint is marked as deprecated but is still responding. It failed schema validation, suggesting it might be returning a generic error or WAF block page, but it should still be investigated."
		}

		return &model.Finding{
			ID:          uuid.New().String(),
			Strategy:    model.StrategyDeprecatedAlive,
			Severity:    severity,
			Title:       "Deprecated endpoint still alive",
			Description: desc,
			Path:        r.Probe.Path,
			Method:      r.Probe.Method,
			Target:      r.Probe.URL,
			StatusCode:  r.StatusCode,
			Evidence:    model.FormatEvidence(r),
			Remediation: "Decommission this endpoint by removing it from the server/gateway. " +
				"If it must remain temporarily, ensure it has the same security controls as active endpoints.",
			Timestamp: time.Now().UTC(),
		}
	}
	return nil
}

func analyzeVersionProbe(r *model.ProbeResult, baseline *model.ProbeResult) *model.Finding {
	if r.StatusCode >= 200 && r.StatusCode < 400 {
		if isCatchAll(r, baseline) {
			return nil // False positive
		}
		severity := model.SeverityCritical
		title := "Old API version still accessible"
		desc := "A previous version of this API endpoint is still responding, and its response matches the expected schema. This is a Confirmed Zombie API."

		if meta, ok := r.Probe.Meta["direction"]; ok && meta == "newer" {
			severity = model.SeverityMedium
			title = "Newer API version detected (possibly unstaged)"
			desc = "A newer version of this API endpoint was found responding. " +
				"This may be an unstaged or pre-release endpoint that should not be publicly accessible."
		}
		
		schemaStr := r.Probe.Meta["responses_schema"]
		contentType := ""
		if ctVals, ok := r.Headers["Content-Type"]; ok && len(ctVals) > 0 {
			contentType = ctVals[0]
		}
		
		valid, _ := ValidateSchema(schemaStr, r.StatusCode, contentType, r.Body)
		if !valid {
			if hasRetirementKeywords(r.Body) {
				return nil // False positive: Gracefully retired
			}
			if severity == model.SeverityCritical {
				severity = model.SeverityMedium
			}
			desc = "An alternate version of this endpoint is responding. It failed schema validation, suggesting it might be returning a generic error or WAF block page, but it should still be investigated."
		}

		return &model.Finding{
			ID:          uuid.New().String(),
			Strategy:    model.StrategyVersionProbe,
			Severity:    severity,
			Title:       title,
			Description: desc,
			Path:        r.Probe.Path,
			Method:      r.Probe.Method,
			Target:      r.Probe.URL,
			StatusCode:  r.StatusCode,
			Evidence:    model.FormatEvidence(r),
			Remediation: "Decommission old API versions and ensure only the current version is accessible. " +
				"Use API gateway rules to block requests to deprecated version prefixes.",
			Timestamp: time.Now().UTC(),
		}
	}
	return nil
}

func analyzeMethodProbe(r *model.ProbeResult, baseline *model.ProbeResult) *model.Finding {
	// If the server responds with anything other than 405/501 → potential issue
	if r.StatusCode != 405 && r.StatusCode != 501 && r.StatusCode >= 200 && r.StatusCode < 500 {
		if isCatchAll(r, baseline) {
			return nil
		}
		return &model.Finding{
			ID:       uuid.New().String(),
			Strategy: model.StrategyMethodProbe,
			Severity: model.SeverityMedium,
			Title:    "Undocumented HTTP method accepted",
			Description: "This endpoint accepts an HTTP method that is not documented in the API specification. " +
				"Undocumented methods may expose unintended operations (e.g., DELETE on a read-only endpoint).",
			Path:       r.Probe.Path,
			Method:     r.Probe.Method,
			Target:     r.Probe.URL,
			StatusCode: r.StatusCode,
			Evidence:   model.FormatEvidence(r),
			Remediation: "Configure the server or API gateway to explicitly reject HTTP methods that are not " +
				"defined in the API specification. Return 405 Method Not Allowed for unsupported methods.",
			Timestamp: time.Now().UTC(),
		}
	}
	return nil
}

func analyzeShadowPath(r *model.ProbeResult, baseline *model.ProbeResult) *model.Finding {
	if r.StatusCode >= 200 && r.StatusCode < 400 {
		if isCatchAll(r, baseline) {
			return nil
		}
		severity := model.SeverityHigh
		remediation := "Remove or restrict access to this endpoint. If it is intentional, " +
			"document it in the API specification and apply appropriate security controls."

		// Classify severity by path type
		if meta, ok := r.Probe.Meta["category"]; ok {
			switch meta {
			case "debug":
				severity = model.SeverityCritical
				remediation = "IMMEDIATELY remove debug/admin endpoints from production. " +
					"These endpoints can expose sensitive internal data and application state."
			case "docs":
				severity = model.SeverityLow
				remediation = "If API documentation should not be public, restrict access to it. " +
					"Otherwise, consider adding it to the spec."
			case "monitoring":
				severity = model.SeverityMedium
				remediation = "Restrict access to monitoring endpoints (health, metrics) behind authentication " +
					"or network-level controls. These can leak infrastructure information."
			}
		}

		return &model.Finding{
			ID:       uuid.New().String(),
			Strategy: model.StrategyShadowPath,
			Severity: severity,
			Title:    "Shadow/undocumented endpoint found",
			Description: "An endpoint was found that is not documented in the API specification. " +
				"Shadow APIs are a significant security risk as they often lack proper " +
				"authentication, authorization, and monitoring.",
			Path:        r.Probe.Path,
			Method:      r.Probe.Method,
			Target:      r.Probe.URL,
			StatusCode:  r.StatusCode,
			Evidence:    model.FormatEvidence(r),
			Remediation: remediation,
			Timestamp:   time.Now().UTC(),
		}
	}
	return nil
}

func analyzeAuthBypass(r *model.ProbeResult, baseline *model.ProbeResult) *model.Finding {
	if r.StatusCode >= 200 && r.StatusCode < 300 {
		if isCatchAll(r, baseline) {
			return nil
		}
		return &model.Finding{
			ID:       uuid.New().String(),
			Strategy: model.StrategyAuthBypass,
			Severity: model.SeverityCritical,
			Title:    "Authentication bypass on deprecated endpoint",
			Description: "A deprecated endpoint that is still alive responds successfully " +
				"even WITHOUT authentication headers. This is a critical security vulnerability " +
				"as it allows unauthenticated access to deprecated functionality.",
			Path:       r.Probe.Path,
			Method:     r.Probe.Method,
			Target:     r.Probe.URL,
			StatusCode: r.StatusCode,
			Evidence:   model.FormatEvidence(r),
			Remediation: "IMMEDIATELY decommission this endpoint or add authentication enforcement. " +
				"Deprecated endpoints without authentication are prime targets for attackers.",
			Timestamp: time.Now().UTC(),
		}
	}
	return nil
}

func isCatchAll(r *model.ProbeResult, baseline *model.ProbeResult) bool {
	if baseline == nil || baseline.Error != nil {
		return false
	}
	if r.StatusCode != baseline.StatusCode {
		return false
	}
	// If the body is exactly the same, it's a catch-all
	if r.Body == baseline.Body {
		return true
	}
	// Simple length diff heuristic
	diff := len(r.Body) - len(baseline.Body)
	if diff < 0 {
		diff = -diff
	}
	if diff < 50 && r.StatusCode == 200 { // 50 bytes tolerance for dynamic IDs
		return true
	}
	return false
}

func hasRetirementKeywords(body string) bool {
	lowerBody := strings.ToLower(body)
	keywords := []string{"deprecated", "retired", "sunset", "moved", "obsolete", "no longer supported"}
	for _, kw := range keywords {
		if strings.Contains(lowerBody, kw) {
			return true
		}
	}
	return false
}
