// SPDX-License-Identifier: Apache-2.0

// Package store provides the in-memory weather data store cell.
package store

import (
	"log/slog"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"weather-alert-hive/pkg/model"
)

// Cell is the Hive cell for the weather data store.
var Cell = cell.Module(
	"store",
	"Weather data store",

	cell.Config(Config{MaxReadings: 100}),
	cell.Provide(New),
)

// Config holds store configuration.
type Config struct {
	MaxReadings int `mapstructure:"store-max-readings"`
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Int("store-max-readings", c.MaxReadings, "Maximum readings to keep in memory")
}

// Store holds recent weather readings and notifies subscribers.
type Store struct {
	Mu        sync.RWMutex
	Readings  []model.WeatherReading
	maxSize   int
	listeners []chan model.WeatherReading
	log       *slog.Logger
}

type params struct {
	cell.In

	Log    *slog.Logger
	Config Config
}

// New creates a new Store instance.
func New(p params) *Store {
	p.Log.Info("Store initialized", "maxReadings", p.Config.MaxReadings)
	return &Store{
		Readings: make([]model.WeatherReading, 0, p.Config.MaxReadings),
		maxSize:  p.Config.MaxReadings,
		log:      p.Log,
	}
}

// RecordReading stores a reading and notifies all subscribers.
func (s *Store) RecordReading(r model.WeatherReading) {
	s.Mu.Lock()
	if len(s.Readings) >= s.maxSize {
		s.Readings = s.Readings[1:]
	}
	s.Readings = append(s.Readings, r)
	listeners := make([]chan model.WeatherReading, len(s.listeners))
	copy(listeners, s.listeners)
	s.Mu.Unlock()

	for _, ch := range listeners {
		select {
		case ch <- r:
		default:
		}
	}
}

// Watch returns a channel that receives new readings.
func (s *Store) Watch() <-chan model.WeatherReading {
	ch := make(chan model.WeatherReading, 10)
	s.Mu.Lock()
	s.listeners = append(s.listeners, ch)
	s.Mu.Unlock()
	return ch
}

// GetLatest returns the most recent reading.
func (s *Store) GetLatest() (model.WeatherReading, bool) {
	s.Mu.RLock()
	defer s.Mu.RUnlock()
	if len(s.Readings) == 0 {
		return model.WeatherReading{}, false
	}
	return s.Readings[len(s.Readings)-1], true
}

// Count returns the number of stored readings.
func (s *Store) Count() int {
	s.Mu.RLock()
	defer s.Mu.RUnlock()
	return len(s.Readings)
}
