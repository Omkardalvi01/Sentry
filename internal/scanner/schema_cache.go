package scanner

import (
	"encoding/json"
	"fmt"
	"mime"
	"strconv"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	SchemaMatched     = "matched"
	SchemaMismatched  = "mismatched"
	SchemaUnavailable = "unavailable"
	SchemaTruncated   = "truncated"
)

var schemaCache sync.Map

// InspectSchema separates lack of evidence from actual agreement. Each compiler
// is local to a cache miss; compiled schemas can safely be shared by workers.
func InspectSchema(responsesJSON string, status int, contentType, body string, truncated bool) (string, error) {
	if truncated {
		return SchemaTruncated, nil
	}
	if responsesJSON == "" {
		return SchemaUnavailable, nil
	}
	var responses map[string]struct {
		Content map[string]struct {
			Schema any `json:"schema"`
		} `json:"content"`
	}
	if err := json.Unmarshal([]byte(responsesJSON), &responses); err != nil {
		return SchemaUnavailable, err
	}
	node, ok := responses[strconv.Itoa(status)]
	if !ok {
		node, ok = responses[fmt.Sprintf("%dXX", status/100)]
	}
	if !ok {
		node, ok = responses["default"]
	}
	if !ok {
		return SchemaUnavailable, nil
	}
	media, _, _ := mime.ParseMediaType(contentType)
	selected, ok := node.Content[media]
	if !ok && strings.HasSuffix(media, "+json") {
		selected, ok = node.Content["application/json"]
	}
	if !ok || selected.Schema == nil {
		return SchemaUnavailable, nil
	}
	if media != "application/json" && !strings.HasSuffix(media, "+json") {
		return SchemaUnavailable, nil
	}
	raw, _ := json.Marshal(selected.Schema)
	if strings.Contains(string(raw), `"x-sentry-unsupported"`) {
		return SchemaUnavailable, fmt.Errorf("schema contains unsupported recursive reference")
	}
	key := string(raw)
	var schema *jsonschema.Schema
	if cached, ok := schemaCache.Load(key); ok {
		schema = cached.(*jsonschema.Schema)
	} else {
		compiler := jsonschema.NewCompiler()
		if err := compiler.AddResource("https://sentry.local/schema", selected.Schema); err != nil {
			return SchemaUnavailable, err
		}
		compiled, err := compiler.Compile("https://sentry.local/schema")
		if err != nil {
			return SchemaUnavailable, err
		}
		actual, _ := schemaCache.LoadOrStore(key, compiled)
		schema = actual.(*jsonschema.Schema)
	}
	var value any
	if err := json.Unmarshal([]byte(body), &value); err != nil {
		return SchemaMismatched, err
	}
	if err := schema.Validate(value); err != nil {
		return SchemaMismatched, err
	}
	return SchemaMatched, nil
}
func ValidateSchema(responsesJSON string, status int, contentType, body string) (bool, error) {
	state, err := InspectSchema(responsesJSON, status, contentType, body, false)
	return state == SchemaMatched, err
}
