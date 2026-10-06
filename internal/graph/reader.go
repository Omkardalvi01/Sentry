package graph

import (
	"context"
	"fmt"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/Omkardalvi01/sentry/internal/model"
)

// ReadOperations fetches all operations from the graph, optionally filtered by spec.
func (c *Client) ReadOperations(ctx context.Context, specTitle, specVersion string) ([]model.Operation, error) {
	session := c.Session(ctx)
	defer session.Close(ctx)

	query := `
		MATCH (s:Spec)-[:HAS_PATH]->(p:Path)-[:HAS_OPERATION]->(o:Operation)
		WHERE ($specTitle = "" OR s.title = $specTitle)
		  AND ($specVersion = "" OR s.version = $specVersion)
		RETURN o.method AS method, o.operationId AS operationId, o.path AS path,
		       o.summary AS summary, o.description AS description, o.deprecated AS deprecated,
		       o.parameters AS parameters, o.requestBody AS requestBody,
		       o.responses AS responses, o.security AS security, s.title AS specTitle, s.version AS specVersion, o.authHeaders AS authHeaders, o.authQuery AS authQuery, o.tags AS tags
	`

	result, err := session.Run(ctx, query, map[string]interface{}{
		"specTitle":   specTitle,
		"specVersion": specVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("querying operations: %w", err)
	}

	var ops []model.Operation
	for result.Next(ctx) {
		record := result.Record()
		op := model.Operation{
			SpecTitle:    stringVal(record, "specTitle"),
			SpecVersion:  stringVal(record, "specVersion"),
			PathTemplate: stringVal(record, "path"),
			Method:       stringVal(record, "method"),
			AuthHeaders:  stringsVal(record, "authHeaders"), AuthQuery: stringsVal(record, "authQuery"), Tags: stringsVal(record, "tags"),
			OperationID: stringVal(record, "operationId"),
			Summary:     stringVal(record, "summary"),
			Description: stringVal(record, "description"),
			Deprecated:  boolVal(record, "deprecated"),
			Parameters:  stringVal(record, "parameters"),
			RequestBody: stringVal(record, "requestBody"),
			Responses:   stringVal(record, "responses"),
			Security:    stringVal(record, "security"),
		}
		ops = append(ops, op)
	}
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("iterating operations: %w", err)
	}
	return ops, nil
}

// OperationWithPath bundles an operation with its path template for scanning.
type OperationWithPath struct {
	model.Operation
	PathTemplate string
}

// ReadOperationsWithPaths fetches all operations along with their path templates.
func (c *Client) ReadOperationsWithPaths(ctx context.Context, specTitle, specVersion string) ([]OperationWithPath, error) {
	session := c.Session(ctx)
	defer session.Close(ctx)

	query := `
		MATCH (s:Spec)-[:HAS_PATH]->(p:Path)-[:HAS_OPERATION]->(o:Operation)
		WHERE ($specTitle = "" OR s.title = $specTitle)
		  AND ($specVersion = "" OR s.version = $specVersion)
		RETURN o.method AS method, o.operationId AS operationId, o.path AS path,
		       o.summary AS summary, o.description AS description, o.deprecated AS deprecated,
		       o.parameters AS parameters, o.requestBody AS requestBody,
		       o.responses AS responses, o.security AS security, s.title AS specTitle, s.version AS specVersion, o.authHeaders AS authHeaders, o.authQuery AS authQuery, o.tags AS tags,
		       p.template AS pathTemplate
	`

	result, err := session.Run(ctx, query, map[string]interface{}{
		"specTitle":   specTitle,
		"specVersion": specVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("querying operations: %w", err)
	}

	var ops []OperationWithPath
	for result.Next(ctx) {
		record := result.Record()
		owp := OperationWithPath{
			Operation: model.Operation{
				SpecTitle:    stringVal(record, "specTitle"),
				SpecVersion:  stringVal(record, "specVersion"),
				PathTemplate: stringVal(record, "path"),
				Method:       stringVal(record, "method"),
				AuthHeaders:  stringsVal(record, "authHeaders"), AuthQuery: stringsVal(record, "authQuery"), Tags: stringsVal(record, "tags"),
				OperationID: stringVal(record, "operationId"),
				Summary:     stringVal(record, "summary"),
				Description: stringVal(record, "description"),
				Deprecated:  boolVal(record, "deprecated"),
				Parameters:  stringVal(record, "parameters"),
				RequestBody: stringVal(record, "requestBody"),
				Responses:   stringVal(record, "responses"),
				Security:    stringVal(record, "security"),
			},
			PathTemplate: stringVal(record, "pathTemplate"),
		}
		ops = append(ops, owp)
	}
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("iterating operations: %w", err)
	}
	return ops, nil
}

// ReadServers fetches all server URLs from the graph.
func (c *Client) ReadServers(ctx context.Context, specTitle, specVersion string) ([]model.Server, error) {
	session := c.Session(ctx)
	defer session.Close(ctx)

	query := `
		MATCH (s:Spec)-[:HAS_SERVER]->(srv:Server)
		WHERE ($specTitle = "" OR s.title = $specTitle)
		  AND ($specVersion = "" OR s.version = $specVersion)
		RETURN srv.url AS url, srv.description AS description
	`

	result, err := session.Run(ctx, query, map[string]interface{}{
		"specTitle":   specTitle,
		"specVersion": specVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("querying servers: %w", err)
	}

	var servers []model.Server
	for result.Next(ctx) {
		record := result.Record()
		servers = append(servers, model.Server{
			URL:         stringVal(record, "url"),
			Description: stringVal(record, "description"),
		})
	}
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("iterating servers: %w", err)
	}
	return servers, nil
}

// ReadPaths fetches all unique path templates from the graph.
func (c *Client) ReadPaths(ctx context.Context, specTitle, specVersion string) ([]string, error) {
	session := c.Session(ctx)
	defer session.Close(ctx)

	query := `
		MATCH (s:Spec)-[:HAS_PATH]->(p:Path)
		WHERE ($specTitle = "" OR s.title = $specTitle)
		  AND ($specVersion = "" OR s.version = $specVersion)
		RETURN p.template AS template
	`

	result, err := session.Run(ctx, query, map[string]interface{}{
		"specTitle":   specTitle,
		"specVersion": specVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("querying paths: %w", err)
	}

	var paths []string
	for result.Next(ctx) {
		record := result.Record()
		paths = append(paths, stringVal(record, "template"))
	}
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("iterating paths: %w", err)
	}
	return paths, nil
}

// ReadMethodsForPath returns the HTTP methods defined for a given path template.
func (c *Client) ReadMethodsForPath(ctx context.Context, pathTemplate, specTitle, specVersion string) ([]string, error) {
	session := c.Session(ctx)
	defer session.Close(ctx)

	query := `
		MATCH (s:Spec)-[:HAS_PATH]->(p:Path {template: $template})-[:HAS_OPERATION]->(o:Operation)
		WHERE ($specTitle="" OR s.title=$specTitle) AND ($specVersion="" OR s.version=$specVersion)
		RETURN o.method AS method
	`

	result, err := session.Run(ctx, query, map[string]interface{}{
		"template":  pathTemplate,
		"specTitle": specTitle, "specVersion": specVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("querying methods for path: %w", err)
	}

	var methods []string
	for result.Next(ctx) {
		record := result.Record()
		methods = append(methods, stringVal(record, "method"))
	}
	if err := result.Err(); err != nil {
		return nil, fmt.Errorf("iterating methods: %w", err)
	}
	return methods, nil
}

// WriteScan persists a Scan node to the graph.
func (c *Client) WriteScan(ctx context.Context, scan *model.Scan) error {
	return c.Run(ctx, `
		MERGE (s:Scan {id: $id})
		SET s.target = $target,
		    s.specTitle = $specTitle,
		    s.specVersion = $specVersion,
		    s.startedAt = $startedAt,
		    s.completedAt = $completedAt,
		    s.findingsCount = $findingsCount,
		    s.probesSent = $probesSent,
		    s.status = $status
	`, map[string]interface{}{
		"id":            scan.ID,
		"target":        scan.Target,
		"specTitle":     scan.SpecTitle,
		"specVersion":   scan.SpecVersion,
		"startedAt":     scan.StartedAt.Format(time.RFC3339),
		"completedAt":   scan.CompletedAt.Format(time.RFC3339),
		"findingsCount": scan.FindingsCount,
		"probesSent":    scan.ProbesSent,
		"status":        scan.Status,
	})
}

// WriteFinding persists a Finding node and links it to its Scan.
func (c *Client) WriteFinding(ctx context.Context, finding *model.Finding, scanID string) error {
	return c.Run(ctx, `
		MATCH (scan:Scan {id: $scanId})
		MERGE (f:Finding {id: $id})
		SET f.strategy = $strategy,
		    f.severity = $severity,
		    f.title = $title,
		    f.description = $description,
		    f.path = $path,
		    f.method = $method,
		    f.target = $target,
		    f.statusCode = $statusCode,
		    f.evidence = $evidence,
		    f.remediation = $remediation,
		    f.timestamp = $timestamp, f.confidence=$confidence, f.verification=$verification, f.schemaResult=$schemaResult, f.provenance=$provenance, f.specTitle=$specTitle, f.specVersion=$specVersion
		MERGE (f)-[:BELONGS_TO_SCAN]->(scan)
		WITH f
		OPTIONAL MATCH (o:Operation {method: $method, path: $path, specTitle:$specTitle, specVersion:$specVersion})
		FOREACH (_ IN CASE WHEN o IS NOT NULL THEN [1] ELSE [] END |
		    MERGE (f)-[:FOUND_ON]->(o)
		)
	`, map[string]interface{}{
		"confidence": finding.Confidence, "verification": finding.Verification, "schemaResult": finding.SchemaResult, "provenance": finding.Provenance,
		"scanId":    scanID,
		"specTitle": finding.SpecTitle, "specVersion": finding.SpecVersion,
		"id":          finding.ID,
		"strategy":    finding.Strategy,
		"severity":    finding.Severity,
		"title":       finding.Title,
		"description": finding.Description,
		"path":        finding.Path,
		"method":      finding.Method,
		"target":      finding.Target,
		"statusCode":  finding.StatusCode,
		"evidence":    finding.Evidence,
		"remediation": finding.Remediation,
		"timestamp":   finding.Timestamp.Format(time.RFC3339),
	})
}

// Helper functions for safe value extraction from neo4j records.
func stringVal(record *neo4j.Record, key string) string {
	val, ok := record.Get(key)
	if !ok || val == nil {
		return ""
	}
	s, ok := val.(string)
	if !ok {
		return ""
	}
	return s
}

func boolVal(record *neo4j.Record, key string) bool {
	val, ok := record.Get(key)
	if !ok || val == nil {
		return false
	}
	b, ok := val.(bool)
	if !ok {
		return false
	}
	return b
}

// GraphContext holds inventory features. No service-call topology is inferred.
type GraphContext struct {
	PathTemplate string
	Deprecated   bool
	Security     string
	Tag          string
	SpecTitle    string
	SpecVersion  string
}

func (c *Client) ResolveTrafficContext(ctx context.Context, method, pathTemplate, specTitle, specVersion string) (GraphContext, error) {
	ops, err := c.ReadOperationsWithPaths(ctx, specTitle, specVersion)
	if err != nil {
		return GraphContext{}, err
	}
	var matched []OperationWithPath
	for _, op := range ops {
		if op.PathTemplate == pathTemplate && op.Method == method {
			matched = append(matched, op)
		}
	}
	if len(matched) != 1 {
		return GraphContext{}, fmt.Errorf("expected one scoped operation, found %d", len(matched))
	}
	op := matched[0]
	return GraphContext{PathTemplate: op.PathTemplate, Deprecated: op.Deprecated, Security: op.Security, SpecTitle: op.SpecTitle, SpecVersion: op.SpecVersion}, nil
}

func stringsVal(record *neo4j.Record, key string) []string {
	v, _ := record.Get(key)
	out := []string{}
	if vals, ok := v.([]interface{}); ok {
		for _, val := range vals {
			if s, ok := val.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
