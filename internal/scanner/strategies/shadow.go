package strategies

import (
	"context"

	"github.com/Omkardalvi01/sentry/internal/graph"
	"github.com/Omkardalvi01/sentry/internal/model"

)

// shadowPaths defines common API paths that are frequently forgotten or exposed.
// Each entry has a path, HTTP method, and category for severity classification.
type shadowEntry struct {
	path     string
	method   string
	category string // "debug", "docs", "monitoring", "admin"
}

var shadowPaths = []shadowEntry{
	// API documentation
	{"/swagger.json", "GET", "docs"},
	{"/swagger.yaml", "GET", "docs"},
	{"/swagger-ui/", "GET", "docs"},
	{"/swagger-ui/index.html", "GET", "docs"},
	{"/api-docs", "GET", "docs"},
	{"/api-docs/", "GET", "docs"},
	{"/openapi.json", "GET", "docs"},
	{"/openapi.yaml", "GET", "docs"},
	{"/v2/api-docs", "GET", "docs"},
	{"/v3/api-docs", "GET", "docs"},
	{"/redoc", "GET", "docs"},
	{"/docs", "GET", "docs"},

	// Debug / admin
	{"/admin", "GET", "debug"},
	{"/admin/", "GET", "debug"},
	{"/debug", "GET", "debug"},
	{"/debug/", "GET", "debug"},
	{"/debug/pprof/", "GET", "debug"},
	{"/debug/vars", "GET", "debug"},
	{"/console", "GET", "debug"},
	{"/test", "GET", "debug"},
	{"/internal", "GET", "debug"},
	{"/internal/", "GET", "debug"},

	// Monitoring
	{"/health", "GET", "monitoring"},
	{"/healthz", "GET", "monitoring"},
	{"/health/live", "GET", "monitoring"},
	{"/health/ready", "GET", "monitoring"},
	{"/metrics", "GET", "monitoring"},
	{"/status", "GET", "monitoring"},
	{"/info", "GET", "monitoring"},
	{"/env", "GET", "debug"},
	{"/config", "GET", "debug"},

	// Spring Boot Actuator
	{"/actuator", "GET", "monitoring"},
	{"/actuator/health", "GET", "monitoring"},
	{"/actuator/env", "GET", "debug"},
	{"/actuator/configprops", "GET", "debug"},
	{"/actuator/beans", "GET", "debug"},
	{"/actuator/mappings", "GET", "debug"},
	{"/actuator/heapdump", "GET", "debug"},
	{"/actuator/threaddump", "GET", "debug"},

	// GraphQL
	{"/graphql", "POST", "debug"},
	{"/graphiql", "GET", "debug"},
	{"/graphql/schema", "GET", "debug"},

	// Well-known
	{"/.well-known/openid-configuration", "GET", "docs"},
	{"/.env", "GET", "debug"},
	{"/robots.txt", "GET", "docs"},
	{"/sitemap.xml", "GET", "docs"},
}

// ShadowPath generates probes for common shadow/undocumented API paths.
// Strategy: probe well-known paths that are often accidentally left exposed.
type ShadowPath struct{}

func (s *ShadowPath) Name() string { return model.StrategyShadowPath }

func (s *ShadowPath) GenerateProbes(ctx context.Context, client *graph.Client, cfg *model.ScanConfig) ([]*model.Probe, error) {
	// Get documented paths to filter them out
	documented, err := client.ReadPaths(ctx, cfg.SpecTitle, cfg.SpecVer)
	if err != nil {
		return nil, err
	}
	docSet := make(map[string]bool)
	for _, p := range documented {
		docSet[p] = true
	}

	var probes []*model.Probe
	for _, sp := range shadowPaths {
		// Skip if this path is already documented in the spec
		if docSet[sp.path] {
			continue
		}
		probe := model.MakeProbe(
			cfg.Target,
			sp.path,
			sp.method,
			model.StrategyShadowPath,
			map[string]string{
				"category": sp.category,
			},
		)
		probes = append(probes, probe)
	}
	return probes, nil
}
