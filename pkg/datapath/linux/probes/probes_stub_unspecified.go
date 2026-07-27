// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package probes

import (
	"errors"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// ErrNotSupported indicates that a feature probe is not supported. On non-Linux
// platforms every BPF/kernel feature probe is unsupported.
var ErrNotSupported = errors.New("not supported")

// ProgramHelper is a tuple of a BPF program type and a helper function, used to
// probe whether the given helper is usable from the given program type.
type ProgramHelper struct {
	Program ebpf.ProgramType
	Helper  asm.BuiltinFunc
}

// FeatureProbes stores the results of a set of feature probes.
type FeatureProbes struct {
	ProgramHelpers map[ProgramHelper]bool
}

// The following are dummy implementations of the Linux BPF/kernel feature
// probes. On non-Linux platforms no BPF datapath features are available, so
// every probe reports that the feature is unsupported.

func HaveProgramHelper(logger *slog.Logger, pt ebpf.ProgramType, helper asm.BuiltinFunc) error {
	return ErrNotSupported
}

func HaveLargeInstructionLimit(logger *slog.Logger) error { return ErrNotSupported }

func HaveBoundedLoops(logger *slog.Logger) error { return ErrNotSupported }

func HaveWriteableQueueMapping() error { return ErrNotSupported }

func HaveV2ISA(logger *slog.Logger) error { return ErrNotSupported }

func HaveV3ISA(logger *slog.Logger) error { return ErrNotSupported }

func HaveSKBAdjustRoomL2RoomMACSupport(logger *slog.Logger) error { return ErrNotSupported }

func HaveDeadCodeElim() error { return ErrNotSupported }

func HaveIPv6Support() error { return ErrNotSupported }

func HaveBatchAPI() error { return ErrNotSupported }

func HaveAttachType(pt ebpf.ProgramType, at ebpf.AttachType) error { return ErrNotSupported }

func HaveAttachCgroup() error { return ErrNotSupported }

func HaveManagedNeighbors() error { return ErrNotSupported }

func HaveBPF() error { return ErrNotSupported }

func HaveBPFJIT() error { return ErrNotSupported }

func HaveTCBPF() error { return ErrNotSupported }

func HaveTCX() error { return ErrNotSupported }

func HaveNetkit() error { return ErrNotSupported }

func HaveNetkitScrub() error { return ErrNotSupported }

func HaveFibLookupSkipNeigh() error { return ErrNotSupported }

func HaveFibLookupTbid() error { return ErrNotSupported }

func HaveFibLookupSrc() error { return ErrNotSupported }

func HaveBIGTCPIPv4() error { return ErrNotSupported }

func HaveBIGTCPIPv6() error { return ErrNotSupported }

func HaveBIGTCPTunnel() error { return ErrNotSupported }

// KernelHZ and Jiffies rely on Linux-specific timing information which is not
// available on other platforms.
func KernelHZ() (uint16, error) { return 0, ErrNotSupported }

func Jiffies() (uint64, error) { return 0, ErrNotSupported }

// CreateHeaderFiles and ExecuteHeaderProbes are part of the datapath header
// generation which only runs on Linux.
func CreateHeaderFiles(headerDir string, probes *FeatureProbes) error { return ErrNotSupported }

func ExecuteHeaderProbes(logger *slog.Logger) *FeatureProbes {
	return &FeatureProbes{ProgramHelpers: map[ProgramHelper]bool{}}
}
