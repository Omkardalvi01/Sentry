package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/oasdiff/yaml"

	"github.com/Omkardalvi01/sentry/internal/model"
)

// Swagger2Parser parses Swagger 2.0 specifications by converting them to
// OpenAPI 3.0 and then delegating to the OpenAPI3Parser.
type Swagger2Parser struct{}

// Parse loads a Swagger 2.0 spec, converts it to OpenAPI 3.0, and parses it.
func (p *Swagger2Parser) Parse(filePath string) (*model.Spec, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading Swagger 2.0 spec: %w", err)
	}

	var doc2 openapi2.T

	// Try JSON first, then YAML
	if isJSON(data) {
		if err := json.Unmarshal(data, &doc2); err != nil {
			return nil, fmt.Errorf("parsing Swagger 2.0 JSON: %w", err)
		}
	} else {
		if _, err := yaml.Unmarshal(data, &doc2, yaml.DecodeOpts{DisableTimestamps: true}); err != nil {
			return nil, fmt.Errorf("parsing Swagger 2.0 YAML: %w", err)
		}
	}

	// Convert Swagger 2.0 → OpenAPI 3.0
	doc3, err := openapi2conv.ToV3(&doc2)
	if err != nil {
		return nil, fmt.Errorf("converting Swagger 2.0 to OpenAPI 3.0: %w", err)
	}

	// Validate the converted spec
	ctx := context.Background()
	if err := doc3.Validate(ctx); err != nil {
		return nil, fmt.Errorf("validating converted spec: %w", err)
	}

	// Resolve refs
	doc3.InternalizeRefs(ctx, nil)

	// Reuse OpenAPI 3 extraction logic
	oa3 := &OpenAPI3Parser{}
	spec := &model.Spec{
		Title:       doc3.Info.Title,
		Version:     doc3.Info.Version,
		SpecFormat:  "swagger2",
		SpecVersion: "2.0",
		FilePath:    filePath,
		Description: doc3.Info.Description,
		ImportedAt:  time.Now().UTC(),
	}

	spec.Servers = oa3.extractServers(doc3.Servers)
	spec.Tags = oa3.extractTags(doc3.Tags)

	if doc3.Components != nil {
		spec.Security = oa3.extractSecuritySchemes(doc3.Components.SecuritySchemes)
	}

	spec.Paths = oa3.extractPaths(doc3.Paths)

	return spec, nil
}

// isJSON checks if the data starts with a JSON object or array.
func isJSON(data []byte) bool {
	s := strings.TrimSpace(string(data))
	return len(s) > 0 && (s[0] == '{' || s[0] == '[')
}
