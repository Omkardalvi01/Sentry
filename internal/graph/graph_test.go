package graph

import (
	"context"
	"github.com/Omkardalvi01/sentry/internal/model"
	"os"
	"testing"
	"time"
)

func TestScopedInventoryLive(t *testing.T) {
	uri := os.Getenv("SENTRY_TEST_MEMGRAPH")
	if uri == "" {
		t.Skip("set SENTRY_TEST_MEMGRAPH to a disposable graph")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	g, err := NewClient(uri, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close(ctx)
	if err = EnsureSchema(ctx, g); err != nil {
		t.Fatal(err)
	}
	title := "integration-" + time.Now().Format("150405.000000")
	defer g.Run(ctx, "MATCH (s:Spec {title:$title}) OPTIONAL MATCH (s)-[*1..3]->(n) DETACH DELETE s,n", map[string]interface{}{"title": title})
	for _, version := range []string{"1", "2"} {
		spec := &model.Spec{Title: title, Version: version, ImportedAt: time.Now(), Paths: []model.Path{{Template: "/same", Operations: []model.Operation{{Method: "GET", Summary: version, Security: "[]", Tags: []string{"tag"}}}}}}
		if _, err = NewIngestor(g, false).Ingest(ctx, spec); err != nil {
			t.Fatal(err)
		}
	}
	for _, version := range []string{"1", "2"} {
		ops, err := g.ReadOperationsWithPaths(ctx, title, version)
		if err != nil || len(ops) != 1 || ops[0].Summary != version {
			t.Fatal(ops, err)
		}
	}
	spec := &model.Spec{Title: title, Version: "1", ImportedAt: time.Now(), Paths: []model.Path{{Template: "/new", Operations: []model.Operation{{Method: "GET", Security: "[]"}}}}}
	if _, err = NewIngestor(g, false).Ingest(ctx, spec); err != nil {
		t.Fatal(err)
	}
	ops, err := g.ReadOperationsWithPaths(ctx, title, "1")
	if err != nil || len(ops) != 1 || ops[0].PathTemplate != "/new" {
		t.Fatal(ops, err)
	}
}
