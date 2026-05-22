// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package act

import (
	"context"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/registry"
)

const (
	ACTMapName = "cilium_lb_act"
	FCTMapName = "cilium_lb_fct"
)

var Cell = cell.Module(
	"active-connection-tracking",
	"Windows stub",
	cell.Provide(provide),
	cell.Invoke(configure),
	cell.Config(defaultConfig),
)

type Config struct {
	EnableActiveConnectionTracking bool
}

func (c Config) Flags(fs *pflag.FlagSet) {
	fs.Bool("enable-active-connection-tracking", defaultConfig.EnableActiveConnectionTracking,
		"Count open and active connections to services, grouped by zones defined in fixed-zone-mapping.")
}

var defaultConfig = Config{}

type ACTIterator func(*ActiveConnectionTrackerKey, *ActiveConnectionTrackerValue)

type ACTMap interface {
	IterateWithCallback(context.Context, ACTIterator) error
	Delete(*ActiveConnectionTrackerKey) error
	SaveFailed(*ActiveConnectionTrackerKey, uint64) error
	RestoreFailed(*ActiveConnectionTrackerKey) (uint64, error)
}

func provide(cell.Lifecycle, Config, loadbalancer.Config, *registry.MapRegistry) (bpf.MaybeMapOut[ACTMap], defines.NodeOut, error) {
	return bpf.NoneMap[ACTMap](), defines.NodeOut{}, nil
}

func configure(Config, loadbalancer.Config, *registry.MapRegistry) error {
	return nil
}

type ActiveConnectionTrackerKey struct {
	SvcID uint16 `align:"svc_id"`
	Zone  uint8  `align:"zone"`
	Pad   uint8  `align:"pad"`
}

func (s *ActiveConnectionTrackerKey) New() bpf.MapKey { return &ActiveConnectionTrackerKey{} }

func (v *ActiveConnectionTrackerKey) String() string {
	return fmt.Sprintf("%d[%d]", v.SvcID, v.Zone)
}

type ActiveConnectionTrackerValue struct {
	Opened uint32 `align:"opened"`
	Closed uint32 `align:"closed"`
}

func (s *ActiveConnectionTrackerValue) New() bpf.MapValue { return &ActiveConnectionTrackerValue{} }

func (s *ActiveConnectionTrackerValue) String() string {
	return fmt.Sprintf("+%d -%d", s.Opened, s.Closed)
}

type FailedConnectionTrackerValue struct {
	Failed uint32 `align:"failed"`
}

func (s *FailedConnectionTrackerValue) New() bpf.MapValue { return &FailedConnectionTrackerValue{} }

func (s *FailedConnectionTrackerValue) String() string {
	return fmt.Sprintf("%d", s.Failed)
}
