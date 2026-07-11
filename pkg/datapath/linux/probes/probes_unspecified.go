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

// Dummy values on non-linux platform
const (
	NTF_EXT_LEARNED = iota
	NTF_EXT_MANAGED
)

// ErrNotSupported indicates that a feature is not supported by the current kernel.
var ErrNotSupported = errors.New("not supported")

type ProgramHelper struct {
	Program ebpf.ProgramType
	Helper  asm.BuiltinFunc
}

type FeatureProbes struct {
	ProgramHelpers map[ProgramHelper]bool
}

func HaveProgramHelper(logger *slog.Logger, pt ebpf.ProgramType, helper asm.BuiltinFunc) error {
	return ErrNotSupported
}

func HaveLargeInstructionLimit(logger *slog.Logger) error { return ErrNotSupported }
func HaveBoundedLoops(logger *slog.Logger) error          { return ErrNotSupported }
func HaveWriteableQueueMapping() error                    { return ErrNotSupported }
func HaveV2ISA(logger *slog.Logger) error                 { return ErrNotSupported }
func HaveV3ISA(logger *slog.Logger) error                 { return ErrNotSupported }

var HaveAttachCgroup = func() error { return ErrNotSupported }

func HaveAttachType(pt ebpf.ProgramType, at ebpf.AttachType) error { return ErrNotSupported }

var HaveBPF = func() error { return ErrNotSupported }
var HaveBPFJIT = func() error { return ErrNotSupported }
var HaveTCBPF = func() error { return ErrNotSupported }
var HaveTCX = func() error { return ErrNotSupported }
var HaveNetkit = func() error { return ErrNotSupported }
var HaveNetkitScrub = func() error { return ErrNotSupported }
var HaveNetkitTunableBufferMargins = func() error { return ErrNotSupported }

func HaveSKBAdjustRoomL2RoomMACSupport(logger *slog.Logger) error { return ErrNotSupported }
func HaveDeadCodeElim() error                                     { return ErrNotSupported }
func HaveIPv6Support() error                                      { return ErrNotSupported }

var HaveFibLookupSkipNeigh = func() error { return ErrNotSupported }
var HaveFibLookupTbid = func() error { return ErrNotSupported }
var HaveFibLookupSrc = func() error { return ErrNotSupported }

func CreateHeaderFiles(headerDir string, probes *FeatureProbes) error { return nil }

func ExecuteHeaderProbes(logger *slog.Logger) *FeatureProbes {
	return &FeatureProbes{ProgramHelpers: map[ProgramHelper]bool{}}
}

func HaveBatchAPI() error { return ErrNotSupported }

var HaveBIGTCPIPv4 = func() error { return ErrNotSupported }
var HaveBIGTCPIPv6 = func() error { return ErrNotSupported }
var HaveBIGTCPTunnel = func() error { return ErrNotSupported }

func KernelHZ() (uint16, error) { return 0, ErrNotSupported }
func Jiffies() (uint64, error)  { return 0, ErrNotSupported }

var HaveManagedNeighbors = func() error { return ErrNotSupported }
