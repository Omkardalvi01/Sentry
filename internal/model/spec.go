// Package model defines the internal representation (IR) of an API specification.
// These structs mirror the graph node schema: only topological structure is modeled
// as distinct types, while schema details (parameters, request bodies, responses)
// are stored as JSON-serialized strings on the relevant structs.
package model

import "time"

// Spec is the root representation of an imported API specification.
type Spec struct {
	Title       string
	Version     string
	SpecFormat  string // "openapi3" or "swagger2"
	SpecVersion string // Raw version string, e.g. "3.0.3", "2.0"
	FilePath    string
	Description string
	ImportedAt  time.Time

	Servers  []Server
	Paths    []Path
	Security []SecurityScheme
	Tags     []Tag
}

// Server represents a base URL entry from the specification.
type Server struct {
	URL         string
	Description string
	Variables   string // JSON-serialized server variables with defaults & enums
}

// Path represents a URL path template (e.g. /users/{id}).
type Path struct {
	Template         string
	Summary          string
	CommonParameters string // JSON — parameters shared across all operations on this path
	Operations       []Operation
}

// Operation represents an HTTP operation (e.g. GET /users/{id}).
// This is the primary scanning unit. Schema details are stored as JSON properties
// to keep the graph lean while preserving full spec detail for payload generation.
type Operation struct {
	Method      string
	OperationID string
	Summary     string
	Description string
	Deprecated  bool
	Parameters  string // JSON — full parameter array
	RequestBody string // JSON — full request body object
	Responses   string // JSON — map of status code → response
	Security    string // JSON — security requirements
	Tags        []string
}

// SecurityScheme represents an authentication/authorization mechanism.
type SecurityScheme struct {
	Name             string
	Type             string // apiKey, http, oauth2, openIdConnect
	In               string // header, query, cookie (for apiKey)
	Scheme           string // HTTP auth scheme (e.g. bearer, basic)
	BearerFormat     string
	Flows            string // JSON — OAuth2 flows
	OpenIDConnectURL string
}

// Tag represents a logical grouping of operations.
type Tag struct {
	Name        string
	Description string
}
