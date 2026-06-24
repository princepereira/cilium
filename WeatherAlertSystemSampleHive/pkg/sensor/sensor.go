// SPDX-License-Identifier: Apache-2.0

// Package sensor provides the weather sensor cell that generates periodic readings.
package sensor

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"weather-alert-hive/pkg/model"
	"weather-alert-hive/pkg/store"
)

// Cell is the Hive cell for the weather sensor.
var Cell = cell.Module(
	"sensor",
	"Weather sensor data collector",

	cell.Config(Config{
		PollInterval: 3 * time.Second,
		Location:     "Seattle",
	}),
	cell.Provide(NewSensor),
	cell.Invoke(func(*Sensor) {}), // Force instantiation (leaf cell)
)

// Config holds sensor configuration.
type Config struct {
	PollInterval time.Duration `mapstructure:"sensor-poll-interval"`
	Location     string        `mapstructure:"sensor-location"`
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("sensor-poll-interval", c.PollInterval, "How often to poll sensor data")
	flags.String("sensor-location", c.Location, "Weather station location name")
}

// Sensor fetches weather data on a timer.
type Sensor struct {
	cfg      Config
	log      *slog.Logger
	store    *store.Store
	cancelFn context.CancelFunc
}

type params struct {
	cell.In

	Log       *slog.Logger
	Lifecycle cell.Lifecycle
	Config    Config
	Store     *store.Store
}

// New creates a Sensor and registers lifecycle hooks.
func NewSensor(p params) *Sensor {
	s := &Sensor{
		cfg:   p.Config,
		log:   p.Log,
		store: p.Store,
	}

	p.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			innerCtx, cancel := context.WithCancel(context.Background())
			s.cancelFn = cancel
			go s.pollLoop(innerCtx)
			s.log.Info("Sensor started",
				"location", s.cfg.Location,
				"interval", s.cfg.PollInterval)
			return nil
		},
		OnStop: func(ctx cell.HookContext) error {
			if s.cancelFn != nil {
				s.cancelFn()
			}
			s.log.Info("Sensor stopped")
			return nil
		},
	})

	return s
}

func (s *Sensor) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reading := model.WeatherReading{
				Temperature: 15 + rand.Float64()*25,
				Humidity:    30 + rand.Float64()*60,
				WindSpeed:   rand.Float64() * 100,
				Location:    s.cfg.Location,
				Timestamp:   time.Now(),
			}
			s.store.RecordReading(reading)
			s.log.Info("Sensor reading",
				"temp", fmt.Sprintf("%.1f°C", reading.Temperature),
				"humidity", fmt.Sprintf("%.1f%%", reading.Humidity),
				"wind", fmt.Sprintf("%.1f km/h", reading.WindSpeed))
		}
	}
}
