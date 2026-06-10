// SPDX-License-Identifier: Apache-2.0

// Weather Alert System — Hive Framework Tutorial Example
//
// This demonstrates a 5-cell Hive application with modular packages:
//   Sensor → Store → Alert → Notify + API
//
// Run with: go run ./cmd/weather-alert
// Custom flags: go run ./cmd/weather-alert --sensor-poll-interval=2s --alert-temp-threshold=30.0

package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/hive"
	"github.com/spf13/pflag"

	"weather-alert-hive/pkg/alert"
	"weather-alert-hive/pkg/api"
	"weather-alert-hive/pkg/notify"
	"weather-alert-hive/pkg/sensor"
	"weather-alert-hive/pkg/store"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║   Weather Alert System — Hive Framework Demo            ║")
	fmt.Println("║                                                         ║")
	fmt.Println("║   Cells: Sensor → Store → Alert → Notify + API         ║")
	fmt.Println("║   API: http://localhost:8080                            ║")
	fmt.Println("║   Press Ctrl+C to stop gracefully                       ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()

	h := hive.New(
		// Order doesn't matter — Hive resolves dependencies automatically.
		notify.Cell, // provides *notify.Notifier
		store.Cell,  // provides *store.Store
		alert.Cell,  // needs *store.Store + *notify.Notifier
		sensor.Cell, // needs *store.Store
		api.Cell,    // needs *store.Store
	)

	// Register and parse flags so cell configs get populated.
	flags := pflag.NewFlagSet("weather-alert", pflag.ContinueOnError)
	h.RegisterFlags(flags)
	if err := flags.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}
	h.Viper().BindPFlags(flags)

	// Run blocks until SIGINT/SIGTERM, then stops all cells gracefully.
	if err := h.Run(slog.Default()); err != nil {
		fmt.Fprintf(os.Stderr, "Hive exited with error: %v\n", err)
		os.Exit(1)
	}
}
