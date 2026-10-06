package model

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

func OperationKey(title, version, method, path string) string {
	b, _ := json.Marshal([]string{title, version, strings.ToUpper(method), path})
	return string(b)
}

// MatchTemplate prefers literal routes, then the route with most literal segments.
func MatchTemplate(raw string, templates []string) string {
	if u, err := url.Parse(raw); err == nil {
		raw = u.Path
	}
	candidates := append([]string{}, templates...)
	sort.Slice(candidates, func(i, j int) bool {
		a, b := strings.Count(candidates[i], "{"), strings.Count(candidates[j], "{")
		if a != b {
			return a < b
		}
		return candidates[i] < candidates[j]
	})
	for _, t := range candidates {
		parts := strings.Split(t, "/")
		for i, part := range parts {
			if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
				parts[i] = "[^/]+"
			} else {
				parts[i] = regexp.QuoteMeta(part)
			}
		}
		if regexp.MustCompile("^" + strings.Join(parts, "/") + "$").MatchString(raw) {
			return t
		}
	}
	return raw
}

// OpenAPI requirements are OR alternatives. An empty alternative permits public access.
func RequiresAuth(security string) bool {
	var reqs []map[string]any
	if json.Unmarshal([]byte(security), &reqs) != nil || len(reqs) == 0 {
		return false
	}
	for _, req := range reqs {
		if len(req) == 0 {
			return false
		}
	}
	return true
}

func Mutating(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS":
		return false
	}
	return true
}
