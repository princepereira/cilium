// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package netns

import (
	"fmt"
	"iter"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/cilium/cilium/pkg/datapath/windows/netio"
)

// NetNS represents a Windows network compartment, which is the Windows
// counterpart of a Linux network namespace. Compartment binding is thread-local
// on Windows (SetCurrentThreadCompartmentId), mirroring the per-thread nature of
// Linux network namespaces.
type NetNS struct {
	id netio.CompartmentID
	// owned is true when this handle created the compartment and is therefore
	// responsible for deleting it on Close.
	owned bool
}

// New creates a network compartment and returns a handle to it.
//
// Not calling Close() is an error.
func New() (*NetNS, error) {
	id, err := netio.CreateCompartment()
	if err != nil {
		return nil, fmt.Errorf("create compartment: %w", err)
	}
	return &NetNS{id: id, owned: true}, nil
}

// OpenPinned opens a handle to an existing network compartment. On Windows a
// compartment is identified by its numeric ID rather than a pinned nsfs path,
// so path is interpreted as a decimal compartment ID (optionally the last
// segment of a path-like string).
//
// Not calling Close() is an error.
func OpenPinned(path string) (*NetNS, error) {
	id, err := parseCompartmentID(path)
	if err != nil {
		return nil, err
	}
	return &NetNS{id: id}, nil
}

// Current returns a handle to the network compartment of the calling
// goroutine's underlying OS thread.
func Current() (*NetNS, error) {
	return &NetNS{id: netio.GetCurrentThreadCompartmentId()}, nil
}

// GetNetNSCookie returns a stable identifier for the current compartment. On
// Windows the compartment ID serves as the cookie.
func GetNetNSCookie() (uint64, error) {
	return uint64(netio.GetCurrentThreadCompartmentId()), nil
}

// FD returns the compartment ID. Windows compartments are not represented by a
// file descriptor, so the numeric compartment ID is returned instead.
func (h *NetNS) FD() int {
	if h == nil {
		return -1
	}
	return int(h.id)
}

// Close releases the handle. If this handle created the compartment, the
// compartment is deleted. The host's primary/unspecified compartments are never
// deleted.
func (h *NetNS) Close() error {
	if h == nil || !h.owned {
		return nil
	}
	h.owned = false
	if h.id == netio.UnspecifiedCompartmentID || h.id == netio.PrimaryCompartmentID {
		return nil
	}
	if err := netio.DeleteCompartment(h.id); err != nil {
		return fmt.Errorf("delete compartment %d: %w", h.id, err)
	}
	return nil
}

// Do runs the provided func in the compartment without changing the calling
// thread's compartment.
//
// The code in f and any code called by f must NOT call [runtime.LockOSThread],
// as this could leave the goroutine created by Do permanently pinned to an OS
// thread.
func (h *NetNS) Do(f func() error) error {
	var g errgroup.Group
	g.Go(func() error {
		// Lock the goroutine to its OS thread so the compartment change is
		// isolated. If restoring the compartment fails, the goroutine stays
		// locked and the Go runtime disposes of the OS thread.
		runtime.LockOSThread()

		orig := netio.GetCurrentThreadCompartmentId()

		if err := netio.SetCurrentThreadCompartmentId(h.id); err != nil {
			return fmt.Errorf("set compartment %d: %w (terminating OS thread)", h.id, err)
		}

		ferr := f()

		if err := netio.SetCurrentThreadCompartmentId(orig); err != nil {
			return fmt.Errorf("restore compartment %d: %w (terminating OS thread)", orig, err)
		}

		runtime.UnlockOSThread()
		return ferr
	})

	return g.Wait()
}

// All is not supported on Windows: enumerating network compartments has no
// portable API equivalent.
func All() (iter.Seq2[string, *NetNS], <-chan error) {
	errCh := make(chan error, 1)
	errCh <- fmt.Errorf("enumerating network compartments is not supported on Windows")
	close(errCh)
	return nil, errCh
}

// parseCompartmentID interprets s as a decimal compartment ID. If s looks like a
// path, the last non-empty segment is used.
func parseCompartmentID(s string) (netio.CompartmentID, error) {
	seg := s
	if i := strings.LastIndexAny(seg, `/\`); i >= 0 {
		seg = seg[i+1:]
	}
	seg = strings.TrimSpace(seg)

	v, err := strconv.ParseUint(seg, 10, 32)
	if err != nil {
		return netio.UnspecifiedCompartmentID, fmt.Errorf("invalid compartment ID %q: %w", s, err)
	}
	return netio.CompartmentID(v), nil
}
