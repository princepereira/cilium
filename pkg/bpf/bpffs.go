// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/cilium/pkg/components"
	"github.com/cilium/cilium/pkg/defaults"
)

var (
	// Path to where bpffs is mounted (on Linux) or the pin root (on Windows).
	bpffsRoot = defaults.BPFFSRoot

	// Set to true on first get request to detect misorder
	lockedDown = false
	once       sync.Once
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

// TCGlobalsPath returns the absolute path to <bpffs>/tc/globals, used for
// legacy map pin paths.
func TCGlobalsPath() string {
	once.Do(lockDown)
	return filepath.Join(bpffsRoot, defaults.TCGlobalsPath)
}

// CiliumPath returns the bpffs path to be used for Cilium object pins.
func CiliumPath() string {
	once.Do(lockDown)
	return filepath.Join(bpffsRoot, "cilium")
}

// MkdirBPF wraps [os.MkdirAll] with the right permission bits for bpffs.
// Use this for ensuring the existence of directories on bpffs.
func MkdirBPF(path string) error {
	return os.MkdirAll(path, 0755)
}

// Remove path ignoring ErrNotExist.
func Remove(path string) error {
	err := os.RemoveAll(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing bpffs directory at %s: %w", path, err)
	}
	return err
}

// MapPath returns a path for a BPF map with a given name.
func MapPath(logger *slog.Logger, name string) string {
	if components.IsCiliumAgent() {
		once.Do(lockDown)
		return agentMapPath(name)
	}
	return tcPathFromMountInfo(logger, name)
}

// LocalMapName returns the name for a BPF map that is local to the specified ID.
func LocalMapName(name string, id uint16) string {
	return fmt.Sprintf("%s%05d", name, id)
}

// LocalMapPath returns the path for a BPF map that is local to the specified ID.
func LocalMapPath(logger *slog.Logger, name string, id uint16) string {
	return MapPath(logger, LocalMapName(name, id))
}
