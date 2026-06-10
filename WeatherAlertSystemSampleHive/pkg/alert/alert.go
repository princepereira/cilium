// SPDX-License-Identifier: Apache-2.0

// Package alert provides the weather alert evaluator cell.
package alert

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"weather-alert-hive/pkg/model"
	"weather-alert-hive/pkg/notify"
	"weather-alert-hive/pkg/store"
)

// Cell is the Hive cell for the alert evaluator.
var Cell = cell.Module(
	"alert",
	"Weather alert evaluator",

	cell.Config(Config{
		TempThreshold: 35.0,
		WindThreshold: 80.0,
	}),
	cell.Provide(New),
	cell.Invoke(func(*Evaluator) {}), // Force instantiation (leaf cell)
)

// Config holds alert thresholds.
type Config struct {
	TempThreshold float64 `mapstructure:"alert-temp-threshold"`
	WindThreshold float64 `mapstructure:"alert-wind-threshold"`
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.Float64("alert-temp-threshold", c.TempThreshold, "Temperature alert threshold in Celsius")
	flags.Float64("alert-wind-threshold", c.WindThreshold, "Wind speed alert threshold in km/h")
}

// Evaluator watches the store and produces alerts.
type Evaluator struct {
	cfg      Config
	log      *slog.Logger
	store    *store.Store
	notifier *notify.Notifier
	cancelFn context.CancelFunc
}

type params struct {
	cell.In

	Log       *slog.Logger
	Lifecycle cell.Lifecycle
	Config    Config
	Store     *store.Store
	Notifier  *notify.Notifier
}

// New creates an Evaluator and registers lifecycle hooks.
func New(p params) *Evaluator {
	e := &Evaluator{
		cfg:      p.Config,
		log:      p.Log,
		store:    p.Store,
		notifier: p.Notifier,
	}

	p.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			innerCtx, cancel := context.WithCancel(context.Background())
			e.cancelFn = cancel
			go e.watchLoop(innerCtx)
			e.log.Info("Alert evaluator started",
				"tempThreshold", fmt.Sprintf("%.1f°C", e.cfg.TempThreshold),
				"windThreshold", fmt.Sprintf("%.1f km/h", e.cfg.WindThreshold))
			return nil
		},
		OnStop: func(ctx cell.HookContext) error {
			if e.cancelFn != nil {
				e.cancelFn()
			}
			e.log.Info("Alert evaluator stopped")
			return nil
		},
	})

	return e
}

func (e *Evaluator) watchLoop(ctx context.Context) {
	ch := e.store.Watch()

	for {
		select {
		case <-ctx.Done():
			return
		case reading := <-ch:
			e.evaluate(reading)
		}
	}
}

func (e *Evaluator) evaluate(r model.WeatherReading) {
	if r.Temperature > e.cfg.TempThreshold {
		a := model.Alert{
			Severity: "CRITICAL",
			Message: fmt.Sprintf("HEAT ALERT: %.1f°C exceeds %.1f°C threshold",
				r.Temperature, e.cfg.TempThreshold),
			Reading: r,
		}
		e.log.Warn("Alert triggered", "severity", a.Severity)
		e.notifier.Send(a)
	}

	if r.WindSpeed > e.cfg.WindThreshold {
		a := model.Alert{
			Severity: "WARNING",
			Message: fmt.Sprintf("WIND ALERT: %.1f km/h exceeds %.1f km/h threshold",
				r.WindSpeed, e.cfg.WindThreshold),
			Reading: r,
		}
		e.log.Warn("Alert triggered", "severity", a.Severity)
		e.notifier.Send(a)
	}
}
