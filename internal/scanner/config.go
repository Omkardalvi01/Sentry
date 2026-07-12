package scanner

import (
	"strings"
)



// ParseHeaders parses a slice of "Key: Value" strings into a map.
func ParseHeaders(headers []string) map[string]string {
	m := make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return m
}
