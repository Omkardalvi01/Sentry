// Package parser provides functionality to parse OpenAPI 3.x and Swagger 2.0
// specifications into the internal model representation.
package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Omkardalvi01/sentry/internal/model"
)

// Parser defines the interface for parsing API specifications.
type Parser interface {
	// Parse reads and parses a specification file, returning the internal model.
	Parse(filePath string) (*model.Spec, error)
}

// NewParser creates the appropriate parser based on the spec file content.
// It auto-detects whether the file is OpenAPI 3.x or Swagger 2.0.
func NewParser(filePath string) (Parser, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading spec file: %w", err)
	}

	if isSwagger2(data) {
		return &Swagger2Parser{}, nil
	}
	return &OpenAPI3Parser{}, nil
}

// isSwagger2 detects if the raw spec data is a Swagger 2.0 document.
func isSwagger2(data []byte) bool {
	// Quick check: look for "swagger" key with value "2.0"
	// This works for both JSON and YAML (after basic inspection)
	content := strings.ToLower(string(data))
	if strings.Contains(content, `"swagger"`) || strings.Contains(content, "swagger:") {
		// Try JSON parse first
		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err == nil {
			if v, ok := raw["swagger"]; ok {
				if s, ok := v.(string); ok && strings.HasPrefix(s, "2.") {
					return true
				}
			}
		}
		// For YAML, check for "swagger:" followed by "2." pattern
		if strings.Contains(content, `swagger: "2.`) ||
			strings.Contains(content, "swagger: '2.") ||
			strings.Contains(content, "swagger: 2.") {
			return true
		}
	}
	return false
}
