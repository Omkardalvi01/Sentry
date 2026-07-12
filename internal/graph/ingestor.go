package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/Omkardalvi01/sentry/internal/model"
)

// IngestStats holds counts of nodes and relationships created during ingestion.
type IngestStats struct {
	Specs           int
	Servers         int
	Paths           int
	Operations      int
	SecuritySchemes int
	Tags            int
	Relationships   int
	Duration        time.Duration
}

// String returns a human-readable summary of the ingestion stats.
func (s IngestStats) String() string {
	total := s.Specs + s.Servers + s.Paths + s.Operations + s.SecuritySchemes + s.Tags
	return fmt.Sprintf(
		"  Nodes: %d (%d spec, %d servers, %d tags, %d security, %d paths, %d operations)\n  Edges: %d\n  Time:  %s",
		total, s.Specs, s.Servers, s.Tags, s.SecuritySchemes, s.Paths, s.Operations,
		s.Relationships,
		s.Duration.Round(time.Millisecond),
	)
}

// Ingestor handles ingesting parsed API specs into Memgraph.
type Ingestor struct {
	client  *Client
	verbose bool
}

// NewIngestor creates a new Ingestor.
func NewIngestor(client *Client, verbose bool) *Ingestor {
	return &Ingestor{
		client:  client,
		verbose: verbose,
	}
}

// Ingest writes the entire spec model into Memgraph as a graph.
// It uses MERGE queries to ensure idempotency.
func (ing *Ingestor) Ingest(ctx context.Context, spec *model.Spec) (*IngestStats, error) {
	start := time.Now()
	stats := &IngestStats{}

	err := ing.client.RunInTransaction(ctx, func(tx neo4j.ManagedTransaction) error {
		// 1. Create Spec node
		if err := ing.mergeSpec(ctx, tx, spec, stats); err != nil {
			return fmt.Errorf("merging spec: %w", err)
		}

		// 2. Create Server nodes + HAS_SERVER relationships
		for _, srv := range spec.Servers {
			if err := ing.mergeServer(ctx, tx, spec, &srv, stats); err != nil {
				return fmt.Errorf("merging server %s: %w", srv.URL, err)
			}
		}

		// 3. Create Tag nodes + HAS_TAG relationships
		for _, tag := range spec.Tags {
			if err := ing.mergeTag(ctx, tx, spec, &tag, stats); err != nil {
				return fmt.Errorf("merging tag %s: %w", tag.Name, err)
			}
		}

		// 4. Create SecurityScheme nodes + DEFINES_SECURITY relationships
		for _, sec := range spec.Security {
			if err := ing.mergeSecurityScheme(ctx, tx, spec, &sec, stats); err != nil {
				return fmt.Errorf("merging security scheme %s: %w", sec.Name, err)
			}
		}

		// 5. Create Path nodes + HAS_PATH relationships
		for _, path := range spec.Paths {
			if err := ing.mergePath(ctx, tx, spec, &path, stats); err != nil {
				return fmt.Errorf("merging path %s: %w", path.Template, err)
			}

			// 6. Create Operation nodes + HAS_OPERATION relationships
			for _, op := range path.Operations {
				if err := ing.mergeOperation(ctx, tx, spec, &path, &op, stats); err != nil {
					return fmt.Errorf("merging operation %s %s: %w", op.Method, path.Template, err)
				}

				// 7. Wire TAGGED relationships
				for _, tagName := range op.Tags {
					if err := ing.wireTagged(ctx, tx, &path, &op, tagName, stats); err != nil {
						return fmt.Errorf("wiring tag %s: %w", tagName, err)
					}
				}

				// 8. Wire REQUIRES_SECURITY relationships
				if err := ing.wireSecurityRequirements(ctx, tx, &path, &op, stats); err != nil {
					return fmt.Errorf("wiring security: %w", err)
				}
			}
		}

		return nil
	})

	stats.Duration = time.Since(start)
	return stats, err
}

func (ing *Ingestor) mergeSpec(ctx context.Context, tx neo4j.ManagedTransaction, spec *model.Spec, stats *IngestStats) error {
	query := `
		MERGE (s:Spec {title: $title, version: $version})
		SET s.specFormat = $specFormat,
		    s.specVersion = $specVersion,
		    s.filePath = $filePath,
		    s.description = $description,
		    s.importedAt = $importedAt
	`
	params := map[string]interface{}{
		"title":       spec.Title,
		"version":     spec.Version,
		"specFormat":  spec.SpecFormat,
		"specVersion": spec.SpecVersion,
		"filePath":    spec.FilePath,
		"description": spec.Description,
		"importedAt":  spec.ImportedAt.Format(time.RFC3339),
	}

	if _, err := tx.Run(ctx, query, params); err != nil {
		return err
	}
	stats.Specs++
	ing.log("  + Spec: %s v%s", spec.Title, spec.Version)
	return nil
}

func (ing *Ingestor) mergeServer(ctx context.Context, tx neo4j.ManagedTransaction, spec *model.Spec, srv *model.Server, stats *IngestStats) error {
	query := `
		MATCH (s:Spec {title: $specTitle, version: $specVersion})
		MERGE (srv:Server {url: $url})
		SET srv.description = $description,
		    srv.variables = $variables
		MERGE (s)-[:HAS_SERVER]->(srv)
	`
	params := map[string]interface{}{
		"specTitle":   spec.Title,
		"specVersion": spec.Version,
		"url":         srv.URL,
		"description": srv.Description,
		"variables":   srv.Variables,
	}

	if _, err := tx.Run(ctx, query, params); err != nil {
		return err
	}
	stats.Servers++
	stats.Relationships++
	ing.log("  + Server: %s", srv.URL)
	return nil
}

func (ing *Ingestor) mergeTag(ctx context.Context, tx neo4j.ManagedTransaction, spec *model.Spec, tag *model.Tag, stats *IngestStats) error {
	query := `
		MATCH (s:Spec {title: $specTitle, version: $specVersion})
		MERGE (t:Tag {name: $name})
		SET t.description = $description
		MERGE (s)-[:HAS_TAG]->(t)
	`
	params := map[string]interface{}{
		"specTitle":   spec.Title,
		"specVersion": spec.Version,
		"name":        tag.Name,
		"description": tag.Description,
	}

	if _, err := tx.Run(ctx, query, params); err != nil {
		return err
	}
	stats.Tags++
	stats.Relationships++
	ing.log("  + Tag: %s", tag.Name)
	return nil
}

func (ing *Ingestor) mergeSecurityScheme(ctx context.Context, tx neo4j.ManagedTransaction, spec *model.Spec, sec *model.SecurityScheme, stats *IngestStats) error {
	query := `
		MATCH (s:Spec {title: $specTitle, version: $specVersion})
		MERGE (sc:SecurityScheme {name: $name})
		SET sc.type = $type,
		    sc.in = $in,
		    sc.scheme = $scheme,
		    sc.bearerFormat = $bearerFormat,
		    sc.flows = $flows,
		    sc.openIdConnectUrl = $openIdConnectUrl
		MERGE (s)-[:DEFINES_SECURITY]->(sc)
	`
	params := map[string]interface{}{
		"specTitle":        spec.Title,
		"specVersion":      spec.Version,
		"name":             sec.Name,
		"type":             sec.Type,
		"in":               sec.In,
		"scheme":           sec.Scheme,
		"bearerFormat":     sec.BearerFormat,
		"flows":            sec.Flows,
		"openIdConnectUrl": sec.OpenIDConnectURL,
	}

	if _, err := tx.Run(ctx, query, params); err != nil {
		return err
	}
	stats.SecuritySchemes++
	stats.Relationships++
	ing.log("  + SecurityScheme: %s (%s)", sec.Name, sec.Type)
	return nil
}

func (ing *Ingestor) mergePath(ctx context.Context, tx neo4j.ManagedTransaction, spec *model.Spec, path *model.Path, stats *IngestStats) error {
	query := `
		MATCH (s:Spec {title: $specTitle, version: $specVersion})
		MERGE (p:Path {template: $template})
		SET p.summary = $summary,
		    p.commonParameters = $commonParameters
		MERGE (s)-[:HAS_PATH]->(p)
	`
	params := map[string]interface{}{
		"specTitle":        spec.Title,
		"specVersion":      spec.Version,
		"template":         path.Template,
		"summary":          path.Summary,
		"commonParameters": path.CommonParameters,
	}

	if _, err := tx.Run(ctx, query, params); err != nil {
		return err
	}
	stats.Paths++
	stats.Relationships++
	ing.log("  + Path: %s", path.Template)
	return nil
}

func (ing *Ingestor) mergeOperation(ctx context.Context, tx neo4j.ManagedTransaction, spec *model.Spec, path *model.Path, op *model.Operation, stats *IngestStats) error {
	// Use method + path template as the MERGE key to ensure uniqueness
	query := `
		MATCH (p:Path {template: $pathTemplate})
		MERGE (o:Operation {method: $method, path: $pathTemplate})
		SET o.operationId = $operationId,
		    o.summary = $summary,
		    o.description = $description,
		    o.deprecated = $deprecated,
		    o.parameters = $parameters,
		    o.requestBody = $requestBody,
		    o.responses = $responses,
		    o.security = $security
		MERGE (p)-[:HAS_OPERATION]->(o)
	`
	params := map[string]interface{}{
		"pathTemplate": path.Template,
		"method":       op.Method,
		"operationId":  op.OperationID,
		"summary":      op.Summary,
		"description":  op.Description,
		"deprecated":   op.Deprecated,
		"parameters":   op.Parameters,
		"requestBody":  op.RequestBody,
		"responses":    op.Responses,
		"security":     op.Security,
	}

	if _, err := tx.Run(ctx, query, params); err != nil {
		return err
	}
	stats.Operations++
	stats.Relationships++
	ing.log("    + %s %s", op.Method, path.Template)
	return nil
}

func (ing *Ingestor) wireTagged(ctx context.Context, tx neo4j.ManagedTransaction, path *model.Path, op *model.Operation, tagName string, stats *IngestStats) error {
	query := `
		MATCH (o:Operation {method: $method, path: $pathTemplate})
		MERGE (t:Tag {name: $tagName})
		MERGE (o)-[:TAGGED]->(t)
	`
	params := map[string]interface{}{
		"method":       op.Method,
		"pathTemplate": path.Template,
		"tagName":      tagName,
	}

	if _, err := tx.Run(ctx, query, params); err != nil {
		return err
	}
	stats.Relationships++
	return nil
}

func (ing *Ingestor) wireSecurityRequirements(ctx context.Context, tx neo4j.ManagedTransaction, path *model.Path, op *model.Operation, stats *IngestStats) error {
	if op.Security == "" {
		return nil
	}

	// Extract scheme names from the JSON security requirements
	schemeNames := extractSecuritySchemeNames(op.Security)
	if len(schemeNames) == 0 {
		return nil
	}

	query := `
		MATCH (o:Operation {method: $method, path: $pathTemplate})
		MATCH (sc:SecurityScheme)
		WHERE sc.name IN $schemeNames
		MERGE (o)-[:REQUIRES_SECURITY]->(sc)
	`
	params := map[string]interface{}{
		"method":       op.Method,
		"pathTemplate": path.Template,
		"schemeNames":  schemeNames,
	}

	if _, err := tx.Run(ctx, query, params); err != nil {
		return err
	}
	stats.Relationships += len(schemeNames)
	return nil
}

// extractSecuritySchemeNames parses a JSON security requirements array
// and returns the unique scheme names.
func extractSecuritySchemeNames(securityJSON string) []string {
	if securityJSON == "" {
		return nil
	}

	var reqs []map[string]interface{}
	if err := json.Unmarshal([]byte(securityJSON), &reqs); err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var names []string
	for _, req := range reqs {
		for name := range req {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	return names
}

func (ing *Ingestor) log(format string, args ...interface{}) {
	if ing.verbose {
		fmt.Printf(format+"\n", args...)
	}
}
