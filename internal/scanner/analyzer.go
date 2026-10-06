package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"mime"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Omkardalvi01/sentry/internal/graph"
	"github.com/Omkardalvi01/sentry/internal/model"
	"github.com/google/uuid"
)

func Analyze(_ context.Context, r, baseline *model.ProbeResult, _ *graph.Client) *model.Finding {
	if r.Error != nil || r.StatusCode < 200 || r.StatusCode >= 300 || isCatchAll(r, baseline) {
		return nil
	}
	p := r.Probe
	// HEAD and OPTIONS success alone does not demonstrate an undocumented operation.
	if p.Strategy == model.StrategyMethodProbe && (p.Method == "HEAD" || p.Method == "OPTIONS") {
		return nil
	}
	state, _ := InspectSchema(p.Meta["responses_schema"], r.StatusCode, contentType(r), r.Body, r.Truncated)
	f := &model.Finding{ID: uuid.NewString(), Strategy: p.Strategy, Severity: model.SeverityLow, Path: p.Path, Method: p.Method, Target: model.SafeProbeURL(p), StatusCode: r.StatusCode, Evidence: model.FormatEvidence(r), Timestamp: time.Now().UTC(), Confidence: "medium", Verification: "reachable", SchemaResult: state, Provenance: []string{"active"}, SpecTitle: p.Meta["specTitle"], SpecVersion: p.Meta["specVersion"]}
	if p.Meta["passive"] == "true" {
		f.Provenance = append(f.Provenance, "passive")
	}
	f.OperationKey = model.OperationKey(f.SpecTitle, f.SpecVersion, p.Method, p.Path)
	if state == SchemaMatched {
		f.Confidence = "high"
		f.Verification = "response_verified"
		f.Provenance = append(f.Provenance, "schema")
	}
	if state == SchemaMismatched || state == SchemaTruncated {
		f.Confidence = "low"
		f.Verification = "candidate"
	}
	switch p.Strategy {
	case model.StrategyDeprecatedAlive:
		f.Title = "Deprecated endpoint remains reachable"
		f.Description = "The specification marks this operation deprecated. Reachability is a lifecycle discrepancy; deprecation alone does not establish a vulnerability or a missed retirement deadline."
		f.Provenance = append(f.Provenance, "specification")
		f.Remediation = "Review the lifecycle policy and retire the operation when appropriate."
	case model.StrategyVersionProbe:
		f.Title = "Alternate API version remains reachable"
		f.Description = "An alternate version responds successfully. Verify its inventory and intended exposure."
		f.Remediation = "Document supported versions and retire unsupported versions."
	case model.StrategyMethodProbe:
		f.Title = "Undocumented HTTP method responds successfully"
		f.Description = "An undocumented method has a distinct successful response. Verify that it represents an intended operation."
		f.Severity = model.SeverityMedium
		f.Remediation = "Document intended methods and reject unsupported methods."
	case model.StrategyShadowPath:
		f.Title = "Undocumented endpoint remains reachable"
		f.Description = "A route absent from the selected inventory has a distinct successful response. Its security impact requires review."
		f.Remediation = "Document the route and verify its access controls."
	case model.StrategyAuthBypass:
		if p.Meta["requires_auth"] != "true" || p.Meta["authenticated"] != "true" || r.Truncated {
			return nil
		}
		var authenticated model.ProbeResult
		if json.Unmarshal([]byte(p.Meta["authenticated_response"]), &authenticated) != nil || authenticated.Truncated || !equivalentResponse(r, &authenticated) {
			return nil
		}
		f.Title = "Protected operation accessible without credentials"
		f.Description = "The specification requires authentication, and credential-free access returned equivalent successful content to the authenticated probe."
		f.Severity = model.SeverityHigh
		f.Confidence = "high"
		f.Verification = "authentication_exposure"
		f.Provenance = append(f.Provenance, "specification", "authenticated_comparison")
		f.Remediation = "Enforce the documented authentication requirement or correct the specification."
	default:
		return nil
	}
	return f
}
func contentType(r *model.ProbeResult) string {
	for k, v := range r.Headers {
		if strings.EqualFold(k, "Content-Type") && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

var dynamicValue = regexp.MustCompile(`(?i)([0-9a-f]{8}-[0-9a-f-]{27,}|\b\d{4}-\d\d-\d\dT[^"\s<]+)`)

func normalizedBody(body string) string {
	var value any
	if json.Unmarshal([]byte(body), &value) == nil {
		normalizeJSON(value)
		b, _ := json.Marshal(value)
		return string(b)
	}
	return strings.Join(strings.Fields(dynamicValue.ReplaceAllString(body, "<dynamic>")), " ")
}
func normalizeJSON(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			switch strings.ToLower(k) {
			case "request_id", "requestid", "timestamp", "trace_id", "traceid":
				x[k] = "<dynamic>"
			default:
				normalizeJSON(val)
			}
		}
	case []any:
		for _, val := range x {
			normalizeJSON(val)
		}
	}
}
func equivalentResponse(a, b *model.ProbeResult) bool {
	ma, _, _ := mime.ParseMediaType(contentType(a))
	mb, _, _ := mime.ParseMediaType(contentType(b))
	return a.Error == nil && b.Error == nil && a.StatusCode == b.StatusCode && ma == mb && normalizedBody(a.Body) == normalizedBody(b.Body)
}
func isCatchAll(r, baseline *model.ProbeResult) bool {
	return baseline != nil && !baseline.Truncated && !r.Truncated && equivalentResponse(r, baseline)
}
func hasRetirementKeywords(body string) bool {
	return strings.Contains(strings.ToLower(body), "retired")
}

// Structured evidence remains a JSON string for compatibility with existing reports.
func sortedFindings(findings []*model.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		return fmt.Sprint(findings[i].Strategy, findings[i].Method, findings[i].Path) < fmt.Sprint(findings[j].Strategy, findings[j].Method, findings[j].Path)
	})
}
