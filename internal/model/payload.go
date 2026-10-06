package model

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// ApplyOperation populates examples/defaults and required request fields.
func ApplyOperation(p *Probe, op Operation) {
	if p.Meta == nil {
		p.Meta = map[string]string{}
	}
	p.Meta["specTitle"], p.Meta["specVersion"], p.Meta["responses_schema"] = op.SpecTitle, op.SpecVersion, op.Responses
	p.Meta["requires_auth"] = fmt.Sprint(RequiresAuth(op.Security))
	p.Meta["security"] = op.Security
	p.Meta["auth_headers"] = strings.Join(op.AuthHeaders, ",")
	p.Meta["auth_query"] = strings.Join(op.AuthQuery, ",")
	var params []map[string]any
	_ = json.Unmarshal([]byte(op.Parameters), &params)
	u, _ := url.Parse(p.URL)
	if u == nil {
		return
	}
	query := u.Query()
	resolvedPath := p.Path
	for _, param := range params {
		name, _ := param["name"].(string)
		where, _ := param["in"].(string)
		required, _ := param["required"].(bool)
		if !required && where != "path" {
			continue
		}
		value := param["example"]
		if value == nil {
			schema, _ := param["schema"].(map[string]any)
			value = SampleValue(schema, 0)
		}
		switch where {
		case "query":
			query.Set(name, fmt.Sprint(value))
		case "header":
			p.Headers[name] = fmt.Sprint(value)
		case "path":
			// Replace the generated placeholder, using a reconstructed template to avoid ambiguous substitutions.
			if strings.Contains(p.Path, "{"+name+"}") {
				resolved := strings.ReplaceAll(resolvedPath, "{"+name+"}", fmt.Sprint(value))
				resolvedPath = resolved
				p.Meta["resolved_path"] = resolved
			}
		}
	}
	if resolved := p.Meta["resolved_path"]; resolved != "" {
		base := strings.TrimSuffix(u.Path, BuildURL("", p.Path))
		u.Path = base + BuildURL("", resolved)
	}
	u.RawQuery = query.Encode()
	p.URL = u.String()
	var rb struct {
		Content map[string]struct {
			Schema  map[string]any `json:"schema"`
			Example any            `json:"example"`
		} `json:"content"`
	}
	if json.Unmarshal([]byte(op.RequestBody), &rb) == nil {
		if media, ok := rb.Content["application/json"]; ok {
			v := media.Example
			if v == nil {
				v = SampleValue(media.Schema, 0)
			}
			b, _ := json.Marshal(v)
			p.Body = string(b)
			p.Headers["Content-Type"] = "application/json"
		}
	}
}
func SampleValue(s map[string]any, depth int) any {
	if depth > 8 {
		return nil
	}
	if s == nil {
		return "test"
	}
	for _, k := range []string{"example", "default"} {
		if v, ok := s[k]; ok {
			return v
		}
	}
	if values, ok := s["enum"].([]any); ok && len(values) > 0 {
		return values[0]
	}
	for _, k := range []string{"oneOf", "anyOf"} {
		if values, ok := s[k].([]any); ok && len(values) > 0 {
			child, _ := values[0].(map[string]any)
			return SampleValue(child, depth+1)
		}
	}
	switch s["type"] {
	case "object":
		result := map[string]any{}
		props, _ := s["properties"].(map[string]any)
		required, _ := s["required"].([]any)
		for _, name := range required {
			key, _ := name.(string)
			child, _ := props[key].(map[string]any)
			result[key] = SampleValue(child, depth+1)
		}
		return result
	case "array":
		child, _ := s["items"].(map[string]any)
		return []any{SampleValue(child, depth+1)}
	case "integer", "number":
		if v, ok := s["minimum"]; ok {
			return v
		}
		return 1
	case "boolean":
		return true
	default:
		switch s["format"] {
		case "uuid":
			return "00000000-0000-0000-0000-000000000001"
		case "date":
			return "2026-01-01"
		case "date-time":
			return "2026-01-01T00:00:00Z"
		case "email":
			return "test@example.com"
		}
		return "test"
	}
}
