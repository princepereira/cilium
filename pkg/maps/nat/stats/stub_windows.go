// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package stats

import (
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/time"
)

const TableName = "nat-stats"

var Cell = cell.Module("nat-stats", "Aggregates stats for NAT maps")

type Config struct {
	NATMapStatInterval       time.Duration `mapstructure:"nat-map-stats-interval"`
	NatMapStatKStoredEntries int           `mapstructure:"nat-map-stats-entries"`
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("nat-map-stats-interval", def.NATMapStatInterval, "Interval upon which nat maps are iterated for stats")
	flags.Int("nat-map-stats-entries", def.NatMapStatKStoredEntries, "Number k top stats entries to store locally in statedb")
}

type NatMapStats struct {
	Type       string
	EgressIP   string
	EndpointIP string
	RemotePort uint16
	Proto      string
	Count      int
}
