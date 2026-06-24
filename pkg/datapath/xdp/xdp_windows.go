// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package xdp

import (
	"fmt"

	"github.com/cilium/hive/cell"
)

// AccelerationMode represents the mode to use when loading XDP programs.
type AccelerationMode string

const (
	AccelerationModeNative     AccelerationMode = "native"
	AccelerationModeBestEffort AccelerationMode = "best-effort"
	AccelerationModeGeneric    AccelerationMode = "testing-only"
	AccelerationModeDisabled   AccelerationMode = "disabled"
)

// Mode represents the name of an XDP mode from the perspective of the kernel.
type Mode string

const (
	ModeLinkDriver  Mode = "xdpdrv"
	ModeLinkGeneric Mode = "xdpgeneric"
	ModeLinkNone    Mode = Mode(AccelerationModeDisabled)
)

// Config represents the materialized XDP configuration.
type Config struct {
	mode AccelerationMode
}

type newConfigIn struct {
	cell.In

	Enablers []enabler `group:"request-xdp-mode"`
}

func newConfig(in newConfigIn) (Config, error) {
	cfg := Config{
		mode: AccelerationModeDisabled,
	}

	allValidators := []Validator{}

	for _, e := range in.Enablers {
		switch e.mode {
		case AccelerationModeBestEffort, AccelerationModeNative, AccelerationModeGeneric, AccelerationModeDisabled:
			break
		default:
			return cfg, fmt.Errorf("unknown xdp mode: %s", e.mode)
		}

		if e.mode != cfg.mode {
			allValidators = append(allValidators, e.validators...)

			if cfg.mode == e.mode {
				continue
			}

			if e.mode == AccelerationModeDisabled {
				continue
			}

			if e.mode == AccelerationModeBestEffort && cfg.mode == AccelerationModeNative {
				continue
			} else if cfg.mode == AccelerationModeBestEffort && e.mode == AccelerationModeNative {
				cfg.mode = e.mode
				continue
			}

			if cfg.mode != AccelerationModeDisabled {
				return cfg, fmt.Errorf("XDP mode conflict: trying to set conflicting modes %s and %s",
					cfg.mode, e.mode)
			}

			cfg.mode = e.mode
		}
	}

	for _, v := range allValidators {
		if err := v(cfg.AccelerationMode(), cfg.Mode()); err != nil {
			return cfg, err
		}
	}

	return cfg, nil
}

// AccelerationMode returns the high-level XDP operating mode.
func (cfg Config) AccelerationMode() AccelerationMode { return cfg.mode }

// Mode returns the underlying mode name.
func (cfg Config) Mode() Mode {
	switch cfg.mode {
	case AccelerationModeNative, AccelerationModeBestEffort:
		return ModeLinkDriver
	case AccelerationModeGeneric:
		return ModeLinkGeneric
	}
	return ModeLinkNone
}

// Disabled returns true if XDP is disabled.
func (cfg Config) Disabled() bool { return cfg.mode == AccelerationModeDisabled }

// EnablerOut allows requesting to enable a certain XDP operating mode.
type EnablerOut struct {
	cell.Out
	Enabler enabler `group:"request-xdp-mode"`
}

// NewEnabler returns an object to request a specific XDP mode.
func NewEnabler(mode AccelerationMode, opts ...enablerOpt) EnablerOut {
	enabler := enabler{mode: mode}
	for _, opt := range opts {
		opt(&enabler)
	}
	return EnablerOut{Enabler: enabler}
}

type Validator func(AccelerationMode, Mode) error

// WithValidator registers extra validation functions.
func WithValidator(validator Validator) enablerOpt {
	return func(te *enabler) {
		te.validators = append(te.validators, validator)
	}
}

// WithEnforceXDPDisabled registers a validation function that errors if XDP is enabled.
func WithEnforceXDPDisabled(reason string) enablerOpt {
	return func(te *enabler) {
		te.validators = append(
			te.validators,
			func(m AccelerationMode, _ Mode) error {
				if m != AccelerationModeDisabled {
					return fmt.Errorf("XDP config failed validation: XDP must be disabled because %s", reason)
				}
				return nil
			},
		)
	}
}

type enabler struct {
	mode       AccelerationMode
	validators []Validator
}

type enablerOpt func(*enabler)
