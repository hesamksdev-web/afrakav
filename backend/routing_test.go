package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The host detail route and the per-host ATT&CK route share a prefix. Go's
// ServeMux is supposed to prefer the more specific pattern; this pins that so
// a future route edit cannot silently send /attack into the host handler (or
// make the mux panic on a conflict at startup, which would take the service
// down rather than fail one request).
func TestHostAttackRouteDoesNotCollideWithHostRoute(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/hosts/{ip}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("host:" + r.PathValue("ip")))
	})
	mux.HandleFunc("GET /api/hosts/{ip}/attack", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("attack:" + r.PathValue("ip")))
	})
	mux.HandleFunc("GET /api/attack", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("estate"))
	})
	mux.HandleFunc("GET /api/attack/navigator", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("navigator"))
	})

	cases := map[string]string{
		"/api/hosts/10.20.30.11":        "host:10.20.30.11",
		"/api/hosts/10.20.30.11/attack": "attack:10.20.30.11",
		"/api/attack":                   "estate",
		"/api/attack/navigator":         "navigator",
	}
	for path, want := range cases {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if got := rec.Body.String(); got != want {
			t.Errorf("%s routed to %q, want %q", path, got, want)
		}
	}
}
