package scanner

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

var (
	// schemaCache stores compiled jsonschema.Schema pointers
	// Key: <responses_schema_json>|<status_code>
	schemaCache sync.Map
	// compiler is thread-safe after creation
	compiler = jsonschema.NewCompiler()
)

// ValidateSchema checks if the response body matches the expected schema.
// It returns (matched, error). If the schema doesn't exist for the status code,
// it returns (true, nil) because we only want to fail validation if a schema exists and doesn't match.
func ValidateSchema(responsesJSON string, statusCode int, contentType, body string) (bool, error) {
	if responsesJSON == "" {
		return true, nil // No schema to validate against
	}
	
	// Fast path: check cache
	cacheKey := fmt.Sprintf("%s|%d|%s", responsesJSON, statusCode, contentType)
	if cached, ok := schemaCache.Load(cacheKey); ok {
		if cached == nil {
			return true, nil // cached as "no schema needed"
		}
		schema := cached.(*jsonschema.Schema)
		var v interface{}
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			return false, fmt.Errorf("invalid json body: %w", err)
		}
		if err := schema.Validate(v); err != nil {
			return false, err
		}
		return true, nil
	}

	// Slow path: parse responsesJSON and compile schema
	var responses map[string]interface{}
	if err := json.Unmarshal([]byte(responsesJSON), &responses); err != nil {
		return false, fmt.Errorf("invalid responses json: %w", err)
	}

	// Try specific status code, then "default", then return true (no schema)
	statusStr := fmt.Sprintf("%d", statusCode)
	respNode, ok := responses[statusStr]
	if !ok {
		respNode, ok = responses["default"]
		if !ok {
			schemaCache.Store(cacheKey, nil)
			return true, nil
		}
	}

	respMap, ok := respNode.(map[string]interface{})
	if !ok {
		schemaCache.Store(cacheKey, nil)
		return true, nil
	}

	contentNode, ok := respMap["content"]
	if !ok {
		schemaCache.Store(cacheKey, nil)
		return true, nil
	}
	contentMap, ok := contentNode.(map[string]interface{})
	if !ok {
		schemaCache.Store(cacheKey, nil)
		return true, nil
	}

	// Look for application/json or similar
	var mediaTypeNode interface{}
	for k, v := range contentMap {
		if strings.Contains(strings.ToLower(k), "application/json") {
			mediaTypeNode = v
			break
		}
	}

	if mediaTypeNode == nil {
		schemaCache.Store(cacheKey, nil)
		return true, nil
	}

	mediaTypeMap, ok := mediaTypeNode.(map[string]interface{})
	if !ok {
		schemaCache.Store(cacheKey, nil)
		return true, nil
	}

	schemaNode, ok := mediaTypeMap["schema"]
	if !ok {
		schemaCache.Store(cacheKey, nil)
		return true, nil
	}

	// Compile the schema
	schemaID := fmt.Sprintf("schema://%s", uuid.New().String()) // inline schemas need unique urls sometimes, but AddResource works
	compiler.AddResource(schemaID, schemaNode)
	schema, err := compiler.Compile(schemaID)
	if err != nil {
		return false, fmt.Errorf("compiling schema: %w", err)
	}

	// Cache it
	schemaCache.Store(cacheKey, schema)

	// Validate
	var v interface{}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return false, fmt.Errorf("invalid json body: %w", err)
	}
	if err := schema.Validate(v); err != nil {
		return false, err
	}
	return true, nil
}
