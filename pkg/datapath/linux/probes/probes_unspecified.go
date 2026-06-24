// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package probes

import (
	"errors"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// Dummy values on non-linux platform
const (
	NTF_EXT_LEARNED = iota
	NTF_EXT_MANAGED
)

var ErrNotSupported = errors.New("not supported")

// ProgramHelper represents a BPF program with a specific helper attached.
type ProgramHelper struct {
	Program ebpf.ProgramType
	Helper  asm.BuiltinFunc
}

// FeatureProbes holds the results of BPF feature probing.
type FeatureProbes struct {
	ProgramHelpers map[ProgramHelper]bool
}

var errNotLinux = errors.New("BPF probes not available on non-Linux platforms")

var HaveFibLookupSkipNeigh = sync.OnceValue(func() error { return errNotLinux })
var HaveFibLookupSrc = sync.OnceValue(func() error { return errNotLinux })
var HaveFibLookupTbid = sync.OnceValue(func() error { return errNotLinux })
var HaveAttachCgroup = sync.OnceValue(func() error { return errNotLinux })
var HaveManagedNeighbors = sync.OnceValue(func() error { return errNotLinux })
var HaveBPF = sync.OnceValue(func() error { return errNotLinux })
var HaveBPFJIT = sync.OnceValue(func() error { return errNotLinux })
var HaveTCBPF = sync.OnceValue(func() error { return errNotLinux })
var HaveTCX = sync.OnceValue(func() error { return errNotLinux })
var HaveNetkit = sync.OnceValue(func() error { return errNotLinux })
var HaveNetkitScrub = sync.OnceValue(func() error { return errNotLinux })
var HaveNetkitTunableBufferMargins = sync.OnceValue(func() error { return errNotLinux })
var HaveBIGTCPIPv4 = sync.OnceValue(func() error { return errNotLinux })
var HaveBIGTCPIPv6 = sync.OnceValue(func() error { return errNotLinux })
var HaveBIGTCPTunnel = sync.OnceValue(func() error { return errNotLinux })

func HaveAttachType(pt ebpf.ProgramType, at ebpf.AttachType) error { return errNotLinux }
func KernelHZ() (uint16, error)                                    { return 250, errNotLinux }
func Jiffies() (uint64, error)                                     { return 0, errNotLinux }
func HaveProgramHelper(_ *slog.Logger, _ ebpf.ProgramType, _ asm.BuiltinFunc) error {
	return errNotLinux
}
func HaveLargeInstructionLimit(_ *slog.Logger) error              { return errNotLinux }
func HaveBoundedLoops(_ *slog.Logger) error                       { return errNotLinux }
func HaveWriteableQueueMapping() error                            { return errNotLinux }
func HaveV2ISA(_ *slog.Logger) error                              { return errNotLinux }
func HaveV3ISA(_ *slog.Logger) error                              { return errNotLinux }
func HaveSKBAdjustRoomL2RoomMACSupport(_ *slog.Logger) error      { return errNotLinux }
func HaveDeadCodeElim() error                                     { return errNotLinux }
func HaveIPv6Support() error                                      { return errNotLinux }
func CreateHeaderFiles(_ string, _ *FeatureProbes) error          { return errNotLinux }
func ExecuteHeaderProbes(_ *slog.Logger) *FeatureProbes           { return &FeatureProbes{} }
func HaveBatchAPI() error                                         { return errNotLinux }
