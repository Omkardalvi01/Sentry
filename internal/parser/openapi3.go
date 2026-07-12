package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/Omkardalvi01/sentry/internal/model"
)

// OpenAPI3Parser parses OpenAPI 3.x specifications.
type OpenAPI3Parser struct{}

// Parse loads and parses an OpenAPI 3.x spec file into the internal model.
func (p *OpenAPI3Parser) Parse(filePath string) (*model.Spec, error) {
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true

	doc, err := loader.LoadFromFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("loading OpenAPI 3.x spec: %w", err)
	}

	// Validate the spec
	ctx := context.Background()
	if err := doc.Validate(ctx); err != nil {
		return nil, fmt.Errorf("validating OpenAPI 3.x spec: %w", err)
	}

	// Resolve all InternalizeRefs so that $ref pointers are fully inlined
	doc.InternalizeRefs(ctx, nil)

	spec := &model.Spec{
		Title:       doc.Info.Title,
		Version:     doc.Info.Version,
		SpecFormat:  "openapi3",
		SpecVersion: doc.OpenAPI,
		FilePath:    filePath,
		Description: doc.Info.Description,
		ImportedAt:  time.Now().UTC(),
	}

	// Extract servers
	spec.Servers = p.extractServers(doc.Servers)

	// Extract tags
	spec.Tags = p.extractTags(doc.Tags)

	// Extract security schemes
	if doc.Components != nil {
		spec.Security = p.extractSecuritySchemes(doc.Components.SecuritySchemes)
	}

	// Extract paths and operations
	spec.Paths = p.extractPaths(doc.Paths)

	return spec, nil
}

func (p *OpenAPI3Parser) extractServers(servers openapi3.Servers) []model.Server {
	result := make([]model.Server, 0, len(servers))
	for _, s := range servers {
		srv := model.Server{
			URL:         s.URL,
			Description: s.Description,
		}
		if len(s.Variables) > 0 {
			vars := make(map[string]interface{})
			for name, v := range s.Variables {
				vars[name] = map[string]interface{}{
					"default":     v.Default,
					"description": v.Description,
					"enum":        v.Enum,
				}
			}
			if data, err := json.Marshal(vars); err == nil {
				srv.Variables = string(data)
			}
		}
		result = append(result, srv)
	}
	return result
}

func (p *OpenAPI3Parser) extractTags(tags openapi3.Tags) []model.Tag {
	result := make([]model.Tag, 0, len(tags))
	for _, t := range tags {
		result = append(result, model.Tag{
			Name:        t.Name,
			Description: t.Description,
		})
	}
	return result
}

func (p *OpenAPI3Parser) extractSecuritySchemes(schemes openapi3.SecuritySchemes) []model.SecurityScheme {
	result := make([]model.SecurityScheme, 0, len(schemes))
	for name, ref := range schemes {
		if ref == nil || ref.Value == nil {
			continue
		}
		s := ref.Value
		sec := model.SecurityScheme{
			Name:             name,
			Type:             s.Type,
			In:               s.In,
			Scheme:           s.Scheme,
			BearerFormat:     s.BearerFormat,
			OpenIDConnectURL: s.OpenIdConnectUrl,
		}
		if s.Flows != nil {
			if data, err := json.Marshal(p.serializeOAuthFlows(s.Flows)); err == nil {
				sec.Flows = string(data)
			}
		}
		result = append(result, sec)
	}
	return result
}

func (p *OpenAPI3Parser) serializeOAuthFlows(flows *openapi3.OAuthFlows) map[string]interface{} {
	result := make(map[string]interface{})
	if flows.Implicit != nil {
		result["implicit"] = map[string]interface{}{
			"authorizationUrl": flows.Implicit.AuthorizationURL,
			"tokenUrl":         flows.Implicit.TokenURL,
			"refreshUrl":       flows.Implicit.RefreshURL,
			"scopes":           flows.Implicit.Scopes,
		}
	}
	if flows.Password != nil {
		result["password"] = map[string]interface{}{
			"tokenUrl":   flows.Password.TokenURL,
			"refreshUrl": flows.Password.RefreshURL,
			"scopes":     flows.Password.Scopes,
		}
	}
	if flows.ClientCredentials != nil {
		result["clientCredentials"] = map[string]interface{}{
			"tokenUrl":   flows.ClientCredentials.TokenURL,
			"refreshUrl": flows.ClientCredentials.RefreshURL,
			"scopes":     flows.ClientCredentials.Scopes,
		}
	}
	if flows.AuthorizationCode != nil {
		result["authorizationCode"] = map[string]interface{}{
			"authorizationUrl": flows.AuthorizationCode.AuthorizationURL,
			"tokenUrl":         flows.AuthorizationCode.TokenURL,
			"refreshUrl":       flows.AuthorizationCode.RefreshURL,
			"scopes":           flows.AuthorizationCode.Scopes,
		}
	}
	return result
}

func (p *OpenAPI3Parser) extractPaths(paths *openapi3.Paths) []model.Path {
	if paths == nil {
		return nil
	}

	// Sort paths for deterministic output
	pathKeys := make([]string, 0)
	for path := range paths.Map() {
		pathKeys = append(pathKeys, path)
	}
	sort.Strings(pathKeys)

	result := make([]model.Path, 0, len(pathKeys))
	for _, pathTemplate := range pathKeys {
		pathItem := paths.Map()[pathTemplate]
		if pathItem == nil {
			continue
		}

		mp := model.Path{
			Template: pathTemplate,
			Summary:  pathItem.Summary,
		}

		// Serialize path-level parameters
		if len(pathItem.Parameters) > 0 {
			if data, err := json.Marshal(p.serializeParameters(pathItem.Parameters)); err == nil {
				mp.CommonParameters = string(data)
			}
		}

		// Extract operations for each HTTP method
		mp.Operations = p.extractOperations(pathItem)
		result = append(result, mp)
	}
	return result
}

func (p *OpenAPI3Parser) extractOperations(pathItem *openapi3.PathItem) []model.Operation {
	methods := map[string]*openapi3.Operation{
		"GET":     pathItem.Get,
		"POST":    pathItem.Post,
		"PUT":     pathItem.Put,
		"DELETE":  pathItem.Delete,
		"PATCH":   pathItem.Patch,
		"HEAD":    pathItem.Head,
		"OPTIONS": pathItem.Options,
		"TRACE":   pathItem.Trace,
	}

	// Sort methods for deterministic output
	methodOrder := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"}

	var ops []model.Operation
	for _, method := range methodOrder {
		op := methods[method]
		if op == nil {
			continue
		}
		mop := model.Operation{
			Method:      method,
			OperationID: op.OperationID,
			Summary:     op.Summary,
			Description: op.Description,
			Deprecated:  op.Deprecated,
		}

		// Tags
		mop.Tags = op.Tags

		// Parameters → JSON
		if len(op.Parameters) > 0 {
			if data, err := json.Marshal(p.serializeParameters(op.Parameters)); err == nil {
				mop.Parameters = string(data)
			}
		}

		// RequestBody → JSON
		if op.RequestBody != nil && op.RequestBody.Value != nil {
			if data, err := json.Marshal(p.serializeRequestBody(op.RequestBody.Value)); err == nil {
				mop.RequestBody = string(data)
			}
		}

		// Responses → JSON
		if op.Responses != nil {
			if data, err := json.Marshal(p.serializeResponses(op.Responses)); err == nil {
				mop.Responses = string(data)
			}
		}

		// Security → JSON
		if op.Security != nil {
			if data, err := json.Marshal(p.serializeSecurityRequirements(*op.Security)); err == nil {
				mop.Security = string(data)
			}
		}

		ops = append(ops, mop)
	}
	return ops
}

func (p *OpenAPI3Parser) serializeParameters(params openapi3.Parameters) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(params))
	for _, ref := range params {
		if ref == nil || ref.Value == nil {
			continue
		}
		param := ref.Value
		m := map[string]interface{}{
			"name":     param.Name,
			"in":       param.In,
			"required": param.Required,
		}
		if param.Description != "" {
			m["description"] = param.Description
		}
		if param.Schema != nil && param.Schema.Value != nil {
			m["schema"] = p.serializeSchema(param.Schema.Value)
		}
		if param.Example != nil {
			m["example"] = param.Example
		}
		result = append(result, m)
	}
	return result
}

func (p *OpenAPI3Parser) serializeRequestBody(rb *openapi3.RequestBody) map[string]interface{} {
	result := map[string]interface{}{
		"required":    rb.Required,
		"description": rb.Description,
	}
	if rb.Content != nil {
		content := make(map[string]interface{})
		for mediaType, mt := range rb.Content {
			entry := make(map[string]interface{})
			if mt.Schema != nil && mt.Schema.Value != nil {
				entry["schema"] = p.serializeSchema(mt.Schema.Value)
			}
			if mt.Example != nil {
				entry["example"] = mt.Example
			}
			content[mediaType] = entry
		}
		result["content"] = content
	}
	return result
}

func (p *OpenAPI3Parser) serializeResponses(responses *openapi3.Responses) map[string]interface{} {
	result := make(map[string]interface{})
	for status, ref := range responses.Map() {
		if ref == nil || ref.Value == nil {
			continue
		}
		resp := ref.Value
		entry := map[string]interface{}{
			"description": resp.Description,
		}
		if resp.Content != nil {
			content := make(map[string]interface{})
			for mediaType, mt := range resp.Content {
				c := make(map[string]interface{})
				if mt.Schema != nil && mt.Schema.Value != nil {
					c["schema"] = p.serializeSchema(mt.Schema.Value)
				}
				content[mediaType] = c
			}
			entry["content"] = content
		}
		if resp.Headers != nil {
			headers := make(map[string]interface{})
			for name, hRef := range resp.Headers {
				if hRef != nil && hRef.Value != nil {
					h := map[string]interface{}{
						"description": hRef.Value.Description,
						"required":    hRef.Value.Required,
					}
					if hRef.Value.Schema != nil && hRef.Value.Schema.Value != nil {
						h["schema"] = p.serializeSchema(hRef.Value.Schema.Value)
					}
					headers[name] = h
				}
			}
			entry["headers"] = headers
		}
		result[status] = entry
	}
	return result
}

func (p *OpenAPI3Parser) serializeSecurityRequirements(reqs openapi3.SecurityRequirements) []map[string][]string {
	result := make([]map[string][]string, 0, len(reqs))
	for _, req := range reqs {
		entry := make(map[string][]string)
		for name, scopes := range req {
			entry[name] = scopes
		}
		result = append(result, entry)
	}
	return result
}

// serializeSchema converts an openapi3.Schema to a generic map for JSON serialization.
// It handles nested schemas (properties, items, allOf/oneOf/anyOf) recursively.
func (p *OpenAPI3Parser) serializeSchema(schema *openapi3.Schema) map[string]interface{} {
	if schema == nil {
		return nil
	}

	result := make(map[string]interface{})

	if schema.Type != nil {
		types := schema.Type.Slice()
		if len(types) == 1 {
			result["type"] = types[0]
		} else if len(types) > 1 {
			result["type"] = types
		}
	}
	if schema.Format != "" {
		result["format"] = schema.Format
	}
	if schema.Description != "" {
		result["description"] = schema.Description
	}
	if schema.Nullable {
		result["nullable"] = true
	}
	if len(schema.Enum) > 0 {
		result["enum"] = schema.Enum
	}
	if schema.Default != nil {
		result["default"] = schema.Default
	}
	if schema.Example != nil {
		result["example"] = schema.Example
	}
	if schema.Min != nil {
		result["minimum"] = *schema.Min
	}
	if schema.Max != nil {
		result["maximum"] = *schema.Max
	}
	if schema.MinLength != 0 {
		result["minLength"] = schema.MinLength
	}
	if schema.MaxLength != nil {
		result["maxLength"] = *schema.MaxLength
	}
	if schema.Pattern != "" {
		result["pattern"] = schema.Pattern
	}
	if len(schema.Required) > 0 {
		result["required"] = schema.Required
	}

	// Properties (object type)
	if len(schema.Properties) > 0 {
		props := make(map[string]interface{})
		for name, propRef := range schema.Properties {
			if propRef != nil && propRef.Value != nil {
				props[name] = p.serializeSchema(propRef.Value)
			}
		}
		result["properties"] = props
	}

	// Items (array type)
	if schema.Items != nil && schema.Items.Value != nil {
		result["items"] = p.serializeSchema(schema.Items.Value)
	}

	// Composition
	if len(schema.AllOf) > 0 {
		allOf := make([]interface{}, 0, len(schema.AllOf))
		for _, ref := range schema.AllOf {
			if ref != nil && ref.Value != nil {
				allOf = append(allOf, p.serializeSchema(ref.Value))
			}
		}
		result["allOf"] = allOf
	}
	if len(schema.OneOf) > 0 {
		oneOf := make([]interface{}, 0, len(schema.OneOf))
		for _, ref := range schema.OneOf {
			if ref != nil && ref.Value != nil {
				oneOf = append(oneOf, p.serializeSchema(ref.Value))
			}
		}
		result["oneOf"] = oneOf
	}
	if len(schema.AnyOf) > 0 {
		anyOf := make([]interface{}, 0, len(schema.AnyOf))
		for _, ref := range schema.AnyOf {
			if ref != nil && ref.Value != nil {
				anyOf = append(anyOf, p.serializeSchema(ref.Value))
			}
		}
		result["anyOf"] = anyOf
	}

	return result
}
