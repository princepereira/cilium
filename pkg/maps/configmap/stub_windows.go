// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package configmap

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
)

const MapName = "cilium_runtime_config"

var Cell = cell.Module("config-map", "eBPF map config contains runtime configuration state for the Cilium datapath", cell.Provide(func() Map { return &configMap{} }))

type Index uint32

const (
	UTimeOffset Index = iota
	AgentLiveness
)

func (r Index) String() string { return fmt.Sprintf("%d", r) }

type Value uint64

type Map interface {
	Update(index Index, val uint64) error
	Get(index Index) (uint64, error)
}

type configMap struct{}

func LoadMap(*slog.Logger) (Map, error)      { return &configMap{}, nil }
func (m *configMap) Get(Index) (uint64, error) { return 0, nil }
func (m *configMap) Update(Index, uint64) error { return nil }
