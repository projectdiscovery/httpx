// TODO: move this to internal package
package runner

import (
	"context"
	"time"

	"encoding/json"
	"net/http"
)

type Concurrency struct {
	Threads int `json:"threads"`
}

// Server represents the HTTP server that handles the concurrency settings endpoints.
type Server struct {
	addr       string
	config     *Options
	httpServer *http.Server
}

// New creates a new instance of Server.
func NewServer(addr string, config *Options) *Server {
	return &Server{
		addr:   addr,
		config: config,
	}
}

// Start initializes the server and its routes, then starts listening on the specified address.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/concurrency", s.handleConcurrency)

	s.httpServer = &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	if err := s.httpServer.ListenAndServe(); err != nil {
		return err
	}

	return nil
}

// handleConcurrency routes the request based on its method to the appropriate handler.
func (s *Server) handleConcurrency(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getSettings(w, r)
	case http.MethodPut:
		s.updateSettings(w, r)
	default:
		http.Error(w, "Unsupported HTTP method", http.StatusMethodNotAllowed)
	}
}

// GetSettings handles GET requests and returns the current concurrency settings
func (s *Server) getSettings(w http.ResponseWriter, _ *http.Request) {
	concurrencySettings := Concurrency{
		Threads: s.config.Threads,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(concurrencySettings); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// UpdateSettings handles PUT requests to update the concurrency settings
func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	var newSettings Concurrency
	if err := json.NewDecoder(r.Body).Decode(&newSettings); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if newSettings.Threads > 0 {
		s.config.Threads = newSettings.Threads
	}

	w.WriteHeader(http.StatusOK)
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.httpServer.Shutdown(ctx)
}
