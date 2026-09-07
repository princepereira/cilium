// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package agent

import (
	"context"
	"errors"

	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/monitor/payload"
	"github.com/cilium/cilium/pkg/time"
)

// perfReader is the perf event ring buffer reader. On Linux it is an alias of
// perf.Reader.
type perfReader = perf.Reader

// handleEvents reads events from the perf buffer and processes them. It
// will exit when stopCtx is done. Note, however, that it will block in the
// Poll call but assumes enough events are generated that these blocks are
// short.
func (a *agent) handleEvents(stopCtx context.Context) {
	tNow := time.Now()
	a.logger.Info("Beginning to read perf buffer", logfields.StartTime, tNow)
	defer a.logger.Info("Stopped reading perf buffer", logfields.StartTime, tNow)

	bufferSize := int(a.Pagesize * a.Npages)
	monitorEvents, err := perf.NewReader(a.events, bufferSize)
	if err != nil {
		logging.Fatal(a.logger, "Cannot initialise BPF perf ring buffer sockets",
			logfields.Error, err,
			logfields.StartTime, tNow,
		)
	}
	defer func() {
		monitorEvents.Close()
		a.Lock()
		a.monitorEvents = nil
		a.Unlock()
	}()

	a.Lock()
	a.monitorEvents = monitorEvents
	a.Unlock()

	for !isCtxDone(stopCtx) {
		record, err := monitorEvents.Read()
		switch {
		case isCtxDone(stopCtx):
			return
		case err != nil:
			if perf.IsUnknownEvent(err) {
				a.Lock()
				a.MonitorStatus.Unknown++
				a.Unlock()
			} else {
				a.logger.Warn("Error received while reading from perf buffer",
					logfields.Error, err,
					logfields.StartTime, tNow,
				)
				if errors.Is(err, unix.EBADFD) {
					return
				}
			}
			continue
		}

		a.processPerfRecord(record)
	}
}

// processPerfRecord processes a record from the datapath and sends it to any
// registered subscribers
func (a *agent) processPerfRecord(record perf.Record) {
	a.Lock()
	defer a.Unlock()

	if record.LostSamples > 0 {
		a.MonitorStatus.Lost += int64(record.LostSamples)
		a.notifyPerfEventLostLocked(record.LostSamples, record.CPU)
		a.sendToListenersLocked(&payload.Payload{
			CPU:  record.CPU,
			Lost: record.LostSamples,
			Type: payload.RecordLost,
		})

	} else {
		a.notifyPerfEventLocked(record.RawSample, record.CPU)
		a.sendToListenersLocked(&payload.Payload{
			Data: record.RawSample,
			CPU:  record.CPU,
			Type: payload.EventSample,
		})
	}
}
