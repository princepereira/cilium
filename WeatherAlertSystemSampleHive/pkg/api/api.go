// SPDX-License-Identifier: Apache-2.0

// Package api provides the HTTP API cell for external data injection and queries.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"weather-alert-hive/pkg/model"
	"weather-alert-hive/pkg/store"
)

// Cell is the Hive cell for the HTTP API server.
var Cell = cell.Module(
	"api",
	"HTTP API for weather data injection",

	cell.Config(Config{
		ListenAddr: ":8080",
	}),
	cell.Provide(NewAPIServer),
	cell.Invoke(func(*Server) {}), // Force instantiation (leaf cell)
)

// Config holds API server configuration.
type Config struct {
	ListenAddr string `mapstructure:"api-listen-addr"`
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.String("api-listen-addr", c.ListenAddr, "HTTP API listen address (e.g. :8080)")
}

// Server is the HTTP API server.
type Server struct {
	store  *store.Store
	log    *slog.Logger
	server *http.Server
}

type params struct {
	cell.In

	Log       *slog.Logger
	Lifecycle cell.Lifecycle
	Config    Config
	Store     *store.Store
}

// New creates the API server and registers lifecycle hooks.
func NewAPIServer(p params) *Server {
	mux := http.NewServeMux()
	srv := &Server{
		store: p.Store,
		log:   p.Log,
		server: &http.Server{
			Addr:    p.Config.ListenAddr,
			Handler: mux,
		},
	}

	mux.HandleFunc("/reading", srv.handlePostReading)
	mux.HandleFunc("/readings", srv.handleGetReadings)
	mux.HandleFunc("/health", srv.handleHealth)

	p.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			ln, err := net.Listen("tcp", p.Config.ListenAddr)
			if err != nil {
				return fmt.Errorf("API listen failed: %w", err)
			}
			go srv.server.Serve(ln)
			srv.log.Info("API server started",
				"addr", p.Config.ListenAddr,
				"endpoints", "POST /reading, GET /readings, GET /health")
			return nil
		},
		OnStop: func(ctx cell.HookContext) error {
			srv.log.Info("API server stopping")
			return srv.server.Shutdown(context.Background())
		},
	})

	return srv
}

func (s *Server) handlePostReading(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var input struct {
		Temperature float64 `json:"temperature"`
		Humidity    float64 `json:"humidity"`
		WindSpeed   float64 `json:"wind_speed"`
		Location    string  `json:"location"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if input.Location == "" {
		input.Location = "External"
	}

	reading := model.WeatherReading{
		Temperature: input.Temperature,
		Humidity:    input.Humidity,
		WindSpeed:   input.WindSpeed,
		Location:    input.Location,
		Timestamp:   time.Now(),
	}

	s.store.RecordReading(reading)
	s.log.Info("API: reading injected",
		"temp", fmt.Sprintf("%.1f°C", reading.Temperature),
		"humidity", fmt.Sprintf("%.1f%%", reading.Humidity),
		"wind", fmt.Sprintf("%.1f km/h", reading.WindSpeed),
		"location", reading.Location)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "accepted",
		"message": fmt.Sprintf("Reading recorded: %.1f°C, %.1f%% humidity, %.1f km/h wind", reading.Temperature, reading.Humidity, reading.WindSpeed),
	})
}

func (s *Server) handleGetReadings(w http.ResponseWriter, r *http.Request) {
	s.store.Mu.RLock()
	readings := make([]model.WeatherReading, len(s.store.Readings))
	copy(readings, s.store.Readings)
	s.store.Mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":    len(readings),
		"readings": readings,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	})
}
