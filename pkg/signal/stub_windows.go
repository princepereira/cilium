// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package signal

import (
	"errors"
	"fmt"
	"io"

	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"signal",
	"Receive signals from datapath and distribute them to registered channels",
	cell.Provide(func() SignalManager { return noopSignalManager{} }),
)

type SignalType uint32

const (
	SignalNatFillUp SignalType = iota
	SignalCTFillUp
	SignalAuthRequired
	SignalTypeMax
)

type SignalHandler func(io.Reader) (metricData string, err error)

var (
	ErrFullChannel         = errors.New("full channel")
	ErrNilChannel          = errors.New("nil channel")
	ErrRuntimeRegistration = errors.New("runtime registration not supported")
	ErrNoHandlers          = errors.New("no registered signal handlers")
)

type SignalManager interface {
	RegisterHandler(handler SignalHandler, signals ...SignalType) error
	MuteSignals(signals ...SignalType) error
	UnmuteSignals(signals ...SignalType) error
}

type noopSignalManager struct{}

func (noopSignalManager) RegisterHandler(SignalHandler, ...SignalType) error { return nil }
func (noopSignalManager) MuteSignals(...SignalType) error                    { return nil }
func (noopSignalManager) UnmuteSignals(...SignalType) error                  { return nil }

func ChannelHandler[T fmt.Stringer](ch chan<- T) SignalHandler {
	closed := false
	return func(reader io.Reader) (string, error) {
		if ch == nil {
			return "", ErrNilChannel
		}
		if reader == nil {
			if !closed {
				closed = true
				close(ch)
			}
			return "", io.EOF
		}
		return "", ErrRuntimeRegistration
	}
}
