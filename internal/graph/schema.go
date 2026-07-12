package graph

import (
	"context"
	"fmt"
)

// indexes defines the Memgraph indexes to create for fast MERGE lookups.
var indexes = []string{
	"CREATE INDEX ON :Spec(title);",
	"CREATE INDEX ON :Spec(version);",
	"CREATE INDEX ON :Server(url);",
	"CREATE INDEX ON :Path(template);",
	"CREATE INDEX ON :Operation(operationId);",
	"CREATE INDEX ON :Operation(method);",
	"CREATE INDEX ON :SecurityScheme(name);",
	"CREATE INDEX ON :Tag(name);",
}

// EnsureSchema creates the required indexes in Memgraph.
// Memgraph requires index operations to be in auto-commit (implicit) transactions,
// so each index is created individually via client.Run.
// Memgraph silently ignores duplicate index creation, so this is idempotent.
func EnsureSchema(ctx context.Context, client *Client) error {
	for _, idx := range indexes {
		if err := client.Run(ctx, idx, nil); err != nil {
			return fmt.Errorf("creating index %q: %w", idx, err)
		}
	}
	return nil
}

// WipeAll removes all nodes and relationships from the graph.
// Use with caution — this is destructive.
func WipeAll(ctx context.Context, client *Client) error {
	return client.Run(ctx, "MATCH (n) DETACH DELETE n", nil)
}
