package parser

import (
	"github.com/Omkardalvi01/sentry/internal/model"
	"os"
	"path/filepath"
	"testing"
)

func TestEffectiveSecurityAndParameters(t *testing.T) {
	spec := `{"openapi":"3.0.3","info":{"title":"test","version":"1"},"security":[{"custom":[]}],"components":{"securitySchemes":{"custom":{"type":"apiKey","in":"header","name":"X-Custom-Key"}}},"paths":{"/users/{id}":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"integer"}}],"get":{"responses":{"200":{"description":"ok"}}},"delete":{"security":[],"responses":{"200":{"description":"ok"}}}}}}`
	file := filepath.Join(t.TempDir(), "spec.json")
	os.WriteFile(file, []byte(spec), 0600)
	parsed, err := (&OpenAPI3Parser{}).Parse(file)
	if err != nil {
		t.Fatal(err)
	}
	get, del := parsed.Paths[0].Operations[0], parsed.Paths[0].Operations[1]
	if !model.RequiresAuth(get.Security) || model.RequiresAuth(del.Security) || get.Parameters == "" || len(get.AuthHeaders) != 1 || get.AuthHeaders[0] != "X-Custom-Key" {
		t.Fatal(get, del)
	}
}
