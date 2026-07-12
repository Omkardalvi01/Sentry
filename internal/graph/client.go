// Package graph provides Memgraph connectivity and data ingestion.
package graph

import (
	"context"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Client wraps a Neo4j/Memgraph driver for graph database operations.
type Client struct {
	driver neo4j.DriverWithContext
	uri    string
}

// NewClient creates a new Memgraph client using the Bolt protocol.
// If user and pass are empty, no authentication is used.
func NewClient(uri, user, pass string) (*Client, error) {
	var auth neo4j.AuthToken
	if user != "" {
		auth = neo4j.BasicAuth(user, pass, "")
	} else {
		auth = neo4j.NoAuth()
	}

	driver, err := neo4j.NewDriverWithContext(uri, auth)
	if err != nil {
		return nil, fmt.Errorf("creating Memgraph driver: %w", err)
	}

	return &Client{
		driver: driver,
		uri:    uri,
	}, nil
}

// Ping verifies connectivity to the Memgraph instance.
func (c *Client) Ping(ctx context.Context) error {
	return c.driver.VerifyConnectivity(ctx)
}

// Close shuts down the driver and releases resources.
func (c *Client) Close(ctx context.Context) error {
	return c.driver.Close(ctx)
}

// Session creates a new session for executing queries.
func (c *Client) Session(ctx context.Context) neo4j.SessionWithContext {
	return c.driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: "",
		AccessMode:   neo4j.AccessModeWrite,
	})
}

// Run executes a single Cypher query with parameters in an auto-commit transaction.
func (c *Client) Run(ctx context.Context, cypher string, params map[string]interface{}) error {
	session := c.Session(ctx)
	defer session.Close(ctx)

	_, err := session.Run(ctx, cypher, params)
	if err != nil {
		return fmt.Errorf("executing cypher: %w", err)
	}
	return nil
}

// RunInTransaction executes a function within a write transaction with automatic retry.
func (c *Client) RunInTransaction(ctx context.Context, fn func(tx neo4j.ManagedTransaction) error) error {
	session := c.Session(ctx)
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (interface{}, error) {
		return nil, fn(tx)
	})
	return err
}
