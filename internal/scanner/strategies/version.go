package strategies

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Omkardalvi01/sentry/internal/graph"
	"github.com/Omkardalvi01/sentry/internal/model"

)

// versionRegex matches version patterns like /v1/, /v2/, /api/v1/, etc.
var versionRegex = regexp.MustCompile(`/(v)(\d+)(/|$)`)

// VersionProbe generates probes for API version variants.
// Strategy: if /v2/users exists in spec, probe /v1/users and /v3/users.
type VersionProbe struct{}

func (v *VersionProbe) Name() string { return model.StrategyVersionProbe }

func (v *VersionProbe) GenerateProbes(ctx context.Context, client *graph.Client, cfg *model.ScanConfig) ([]*model.Probe, error) {
	ops, err := client.ReadOperationsWithPaths(ctx, cfg.SpecTitle, cfg.SpecVer)
	if err != nil {
		return nil, err
	}

	// Deduplicate: we probe version variants per path, not per operation
	seenPaths := make(map[string]bool)
	var probes []*model.Probe

	for _, op := range ops {
		path := op.PathTemplate
		if seenPaths[path] {
			continue
		}

		matches := versionRegex.FindStringSubmatchIndex(path)
		if matches == nil {
			continue
		}
		seenPaths[path] = true

		// Extract current version number
		versionStr := path[matches[4]:matches[5]]
		currentVer, err := strconv.Atoi(versionStr)
		if err != nil {
			continue
		}

		// Generate version variants
		variants := generateVersionVariants(path, matches, currentVer)
		for _, variant := range variants {
			probe := model.MakeProbe(
				cfg.Target,
				variant.path,
				op.Method,
				model.StrategyVersionProbe,
				map[string]string{
					"originalPath":    path,
					"originalVersion": fmt.Sprintf("v%d", currentVer),
					"probedVersion":   variant.version,
					"direction":       variant.direction,
					"responses_schema": op.Responses,
				},
			)
			probes = append(probes, probe)
		}
	}

	// Also probe version variants in the target URL itself
	targetVariants := generateTargetVersionVariants(cfg.Target)
	for _, tv := range targetVariants {
		// Re-probe known paths against the alternate target base
		seenPathsForTarget := make(map[string]bool)
		for _, op := range ops {
			if seenPathsForTarget[op.PathTemplate] {
				continue
			}
			seenPathsForTarget[op.PathTemplate] = true
			// Strip the version from the path to avoid double-versioning
			cleanPath := versionRegex.ReplaceAllString(op.PathTemplate, "/")
			probe := model.MakeProbe(
				tv,
				cleanPath,
				op.Method,
				model.StrategyVersionProbe,
				map[string]string{
					"originalTarget": cfg.Target,
					"direction":      "older",
					"responses_schema": op.Responses,
				},
			)
			probes = append(probes, probe)
		}
	}

	return probes, nil
}

type versionVariant struct {
	path      string
	version   string
	direction string // "older" or "newer"
}

func generateVersionVariants(path string, matches []int, currentVer int) []versionVariant {
	var variants []versionVariant

	prefix := path[:matches[2]]
	suffix := path[matches[5]:]
	// matches[5] points to after the digit, then we need the trailing /

	// Older versions
	for v := currentVer - 1; v >= 1 && v >= currentVer-2; v-- {
		newPath := fmt.Sprintf("%sv%d/%s", prefix, v, suffix)
		variants = append(variants, versionVariant{
			path:      newPath,
			version:   fmt.Sprintf("v%d", v),
			direction: "older",
		})
	}

	// Newer versions
	for v := currentVer + 1; v <= currentVer+2; v++ {
		newPath := fmt.Sprintf("%sv%d/%s", prefix, v, suffix)
		variants = append(variants, versionVariant{
			path:      newPath,
			version:   fmt.Sprintf("v%d", v),
			direction: "newer",
		})
	}

	// Unversioned (remove version prefix entirely)
	unversioned := prefix + suffix
	if unversioned != path {
		variants = append(variants, versionVariant{
			path:      unversioned,
			version:   "none",
			direction: "older",
		})
	}

	return variants
}

func generateTargetVersionVariants(target string) []string {
	// Check if the target URL itself contains a version
	matches := versionRegex.FindStringSubmatchIndex(target)
	if matches == nil {
		return nil
	}

	versionStr := target[matches[4]:matches[5]]
	currentVer, err := strconv.Atoi(versionStr)
	if err != nil {
		return nil
	}

	var variants []string
	prefix := target[:matches[2]]
	suffix := target[matches[5]:]

	for v := currentVer - 1; v >= 1 && v >= currentVer-2; v-- {
		variants = append(variants, fmt.Sprintf("%sv%d/%s", prefix, v, strings.TrimLeft(suffix, "/")))
	}

	return variants
}
