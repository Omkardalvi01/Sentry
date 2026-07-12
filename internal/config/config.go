// Package config provides configuration for the Sentry DAST tool.
package config

import "os"

// Config holds all runtime configuration for Sentry.
type Config struct {
	// MemgraphURI is the Bolt protocol URI for the Memgraph instance.
	MemgraphURI string

	// MemgraphUser is the optional username for Memgraph authentication.
	MemgraphUser string

	// MemgraphPass is the optional password for Memgraph authentication.
	MemgraphPass string

	// Clean indicates whether to wipe all existing graph data before import.
	Clean bool

	// Verbose enables detailed logging output.
	Verbose bool
}

// Default returns a Config populated with sensible defaults.
// Environment variables override defaults:
//   - SENTRY_MEMGRAPH_URI
//   - SENTRY_MEMGRAPH_USER
//   - SENTRY_MEMGRAPH_PASS
func Default() *Config {
	cfg := &Config{
		MemgraphURI:  "bolt://localhost:7687",
		MemgraphUser: "",
		MemgraphPass: "",
		Clean:        false,
		Verbose:      false,
	}

	if uri := os.Getenv("SENTRY_MEMGRAPH_URI"); uri != "" {
		cfg.MemgraphURI = uri
	}
	if user := os.Getenv("SENTRY_MEMGRAPH_USER"); user != "" {
		cfg.MemgraphUser = user
	}
	if pass := os.Getenv("SENTRY_MEMGRAPH_PASS"); pass != "" {
		cfg.MemgraphPass = pass
	}

	return cfg
}
