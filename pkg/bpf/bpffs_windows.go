// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package bpf

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/cilium/pkg/components"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	// Path to where bpf map state is stored on Windows.
	bpffsRoot = defaults.BPFFSRoot

	// Set to true on first get request to detect misorder
	lockedDown      = false
	once            sync.Once
	readMountInfo   sync.Once
	mountInfoPrefix string
)

func lockDown() {
	lockedDown = true
}

func setBPFFSRoot(path string) {
	if lockedDown {
		panic("setBPFFSRoot() call after bpffsRoot was read")
	}
	bpffsRoot = path
}

func BPFFSRoot() string {
	once.Do(lockDown)
	return bpffsRoot
}

// TCGlobalsPath returns the path used for map pin paths on Windows.
func TCGlobalsPath() string {
	once.Do(lockDown)
	return filepath.Join(bpffsRoot, defaults.TCGlobalsPath)
}

// CiliumPath returns the path to be used for Cilium object pins on Windows.
func CiliumPath() string {
	once.Do(lockDown)
	return filepath.Join(bpffsRoot, "cilium")
}

// MkdirBPF creates the given directory and any parent directories.
func MkdirBPF(path string) error {
	return os.MkdirAll(path, 0755)
}

// Remove path ignoring ErrNotExist.
func Remove(path string) error {
	err := os.RemoveAll(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing bpf directory at %s: %w", path, err)
	}
	return err
}

// MapPath returns a path for a BPF map with a given name.
func MapPath(logger *slog.Logger, name string) string {
	if components.IsCiliumAgent() {
		once.Do(lockDown)
		return filepath.Join(TCGlobalsPath(), name)
	}
	return filepath.Join(bpffsRoot, defaults.TCGlobalsPath, name)
}

// LocalMapName returns the name for a BPF map that is local to the specified ID.
func LocalMapName(name string, id uint16) string {
	return fmt.Sprintf("%s%05d", name, id)
}

// LocalMapPath returns the path for a BPF map that is local to the specified ID.
func LocalMapPath(logger *slog.Logger, name string, id uint16) string {
	return MapPath(logger, LocalMapName(name, id))
}

var (
	mountOnce sync.Once
)

// CheckOrMountFS on Windows ensures the BPF map directory exists.
// There is no bpffs filesystem on Windows; maps are pinned to regular directories.
func CheckOrMountFS(logger *slog.Logger, bpfRoot string) {
	mountOnce.Do(func() {
		if bpfRoot != "" {
			setBPFFSRoot(bpfRoot)
		}

		if err := os.MkdirAll(bpffsRoot, 0755); err != nil {
			logging.Fatal(logger, "Unable to create BPF map directory", logfields.Error, err)
		}

		tcPath := TCGlobalsPath()
		if err := os.MkdirAll(tcPath, 0755); err != nil {
			logging.Fatal(logger, "Unable to create BPF TC globals directory", logfields.Error, err)
		}

		logger.Info("BPF map directory ready", logfields.BPFFSRoot, bpffsRoot)
	})
}
