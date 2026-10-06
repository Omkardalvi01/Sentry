package model

import "testing"

func TestRouteIdentity(t *testing.T) {
	templates := []string{"/users/{id}", "/users/me", "/users/{id}/items/{item}"}
	for _, tc := range []struct{ raw, want string }{{"/users/me?x=1", "/users/me"}, {"/users/42", "/users/{id}"}, {"/users/42/items/2", "/users/{id}/items/{item}"}, {"/other", "/other"}} {
		if got := MatchTemplate(tc.raw, templates); got != tc.want {
			t.Fatalf("%s: %s", tc.raw, got)
		}
	}
	if OperationKey("a", "1", "get", "/users") == OperationKey("b", "1", "GET", "/users") {
		t.Fatal("cross-spec collision")
	}
}
func TestSecurityAlternatives(t *testing.T) {
	for _, tc := range []struct {
		security string
		want     bool
	}{{`[]`, false}, {`[{"bearer":[]}]`, true}, {`[{},{"bearer":[]}]`, false}, {`garbage`, false}} {
		if RequiresAuth(tc.security) != tc.want {
			t.Fatal(tc)
		}
	}
}
func TestPayload(t *testing.T) {
	op := Operation{Parameters: `[{"name":"id","in":"path","required":true,"example":42},{"name":"sub","in":"path","required":true,"example":7},{"name":"q","in":"query","required":true,"example":"hello world"}]`, RequestBody: `{"content":{"application/json":{"schema":{"type":"object","required":["name"],"properties":{"name":{"type":"string","default":"pet"}}}}}}`}
	p := MakeProbe("http://localhost/api", "/users/{id}/sub/{sub}", "POST", "test", map[string]string{})
	ApplyOperation(p, op)
	if p.URL != "http://localhost/api/users/42/sub/7?q=hello+world" || p.Body != `{"name":"pet"}` {
		t.Fatalf("%s %s", p.URL, p.Body)
	}
}
