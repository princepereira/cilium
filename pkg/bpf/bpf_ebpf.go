// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"errors"
	"fmt"
	"log/slog"
	"path"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf/mapflags"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/spanstat"
)

// createMap wraps a call to ebpf.NewMapWithOptions while measuring syscall duration.
func createMap(spec *ebpf.MapSpec, opts *ebpf.MapOptions) (*ebpf.Map, error) {
	if opts == nil {
		opts = &ebpf.MapOptions{}
	}

	// Translate Linux-tagged map types to the running platform's equivalent
	// (identity on Linux, Linux->Windows mapping on Windows). Cilium's specs
	// use the Linux ebpf.MapType constants, which cilium/ebpf rejects on the
	// native Windows platform.
	spec.Type = ToPlatformMapType(spec.Type)
	spec.Flags = ToPlatformMapFlags(spec.Flags)
	if spec.InnerMap != nil {
		spec.InnerMap.Type = ToPlatformMapType(spec.InnerMap.Type)
		spec.InnerMap.Flags = ToPlatformMapFlags(spec.InnerMap.Flags)
	}

	var duration *spanstat.SpanStat
	if metrics.BPFSyscallDuration.IsEnabled() {
		duration = spanstat.Start()
	}

	m, err := ebpf.NewMapWithOptions(spec, *opts)

	if metrics.BPFSyscallDuration.IsEnabled() {
		metrics.BPFSyscallDuration.WithLabelValues(metricOpCreate, metrics.Error2Outcome(err)).Observe(duration.End(err == nil).Total().Seconds())
	}

	return m, err
}

// OpenOrCreateMap attempts to load the pinned map at "pinDir/<spec.Name>" if
// the spec is marked as Pinned. Any parent directories of pinDir are
// automatically created. Any pinned maps incompatible with the given spec are
// removed and recreated.
//
// If spec.Pinned is 0, a new Map is always created.
func OpenOrCreateMap(logger *slog.Logger, spec *ebpf.MapSpec, pinDir string) (*ebpf.Map, error) {
	var opts ebpf.MapOptions
	if spec.Pinning != 0 {
		if pinDir == "" {
			return nil, errors.New("cannot pin map to empty pinDir")
		}
		if spec.Name == "" {
			return nil, errors.New("cannot load unnamed map from pin")
		}

		if err := MkdirBPF(pinDir); err != nil {
			return nil, fmt.Errorf("creating map base pinning directory: %w", err)
		}

		opts.PinPath = pinDir

		// On upgrade (no flag -> flag): remove BPF_F_RDONLY_PROG from spec
		// to reuse the existing map, since the datapath functions correctly
		// with a more privileged (read-write) map.
		// On downgrade (flag -> no flag): unpin the existing map to force
		// recreation without the flag, since BPF programs need write access.
		pinPath := path.Join(pinDir, spec.Name)
		if existing, err := ebpf.LoadPinnedMap(pinPath, nil); err == nil {
			if info, err := existing.Info(); err == nil {
				const bpfFRdonlyProg = mapflags.BPF_F_RDONLY_PROG
				switch {
				case spec.Flags&bpfFRdonlyProg != 0 && info.Flags&bpfFRdonlyProg == 0:
					// Upgrade: strip flag from spec to reuse existing map.
					spec.Flags &^= bpfFRdonlyProg
				case spec.Flags&bpfFRdonlyProg == 0 && info.Flags&bpfFRdonlyProg != 0:
					// Downgrade: unpin to force recreation without the flag.
					existing.Unpin()
				}
			}
			existing.Close()
		}
	}

	m, err := createMap(spec, &opts)
	if errors.Is(err, ebpf.ErrMapIncompatible) {
		// Found incompatible map. Open the pin again to find out why.
		m, err := ebpf.LoadPinnedMap(path.Join(pinDir, spec.Name), nil)
		if err != nil {
			return nil, fmt.Errorf("open pin of incompatible map: %w", err)
		}
		defer m.Close()

		logger.Info(
			"Unpinning map with incompatible properties",
			logfields.Path, path.Join(pinDir, spec.Name),
			logfields.Old, []any{
				logfields.Type, m.Type(),
				logfields.KeySize, m.KeySize(),
				logfields.ValueSize, m.ValueSize(),
				logfields.MaxEntries, m.MaxEntries(),
				logfields.Flags, m.Flags(),
			},
			logfields.New, []any{
				logfields.Type, spec.Type,
				logfields.KeySize, spec.KeySize,
				logfields.ValueSize, spec.ValueSize,
				logfields.MaxEntries, spec.MaxEntries,
				logfields.Flags, spec.Flags,
			},
		)

		// Existing map incompatible with spec. Unpin so it can be recreated.
		if err := m.Unpin(); err != nil {
			return nil, err
		}

		return createMap(spec, &opts)
	}

	return m, err
}
