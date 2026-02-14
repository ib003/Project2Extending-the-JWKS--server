// Package httpapi provides HTTP handlers and server wiring for the JWKS service.
package httpapi
import (
	"net/http"

	"jwks-server/internal/keys"
)

// Server is a lightweight HTTP server wrapper for the JWKS service.
type Server struct {
	mux *http.ServeMux
}

// NewServer creates a Server with routes for JWKS and auth endpoints.
func NewServer(km *keys.KeyManager) *Server {
	mux := http.NewServeMux()
	h := Handlers{KM: km}

	mux.HandleFunc("/.well-known/jwks.json", h.JWKS)
	mux.HandleFunc("/jwks", h.JWKS)
	mux.HandleFunc("/auth", h.Auth)

	return &Server{mux: mux}
}

// ListenAndServe starts the HTTP server on the given address.
func (s *Server) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s.mux)
}

// Handler returns the underlying HTTP handler (mux). Useful for tests.
func (s *Server) Handler() http.Handler {
	return s.mux
}