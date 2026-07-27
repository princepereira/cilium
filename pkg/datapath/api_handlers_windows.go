// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package datapath

import (
	"github.com/cilium/hive/cell"
	"github.com/go-openapi/runtime/middleware"

	daemonapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	prefilterapi "github.com/cilium/cilium/api/v1/server/restapi/prefilter"
)

// On Linux these REST API handlers are provided by BPF-backed cells
// (pkg/maps, pkg/datapath/prefilter, the node ID handler). Those datapath
// subsystems are not available on non-Linux platforms, so we register stub
// handlers that respond with HTTP 501 Not Implemented. This keeps the API
// server's dependency graph complete and lets the agent start.

const apiNotSupported = "not supported on this platform"

type apiHandlersOut struct {
	cell.Out

	GetMapHandler           daemonapi.GetMapHandler
	GetMapNameHandler       daemonapi.GetMapNameHandler
	GetMapNameEventsHandler daemonapi.GetMapNameEventsHandler
	GetNodeIdsHandler       daemonapi.GetNodeIdsHandler

	GetPrefilterHandler    prefilterapi.GetPrefilterHandler
	PatchPrefilterHandler  prefilterapi.PatchPrefilterHandler
	DeletePrefilterHandler prefilterapi.DeletePrefilterHandler
}

func newStubAPIHandlers() apiHandlersOut {
	return apiHandlersOut{
		GetMapHandler:           daemonapi.GetMapHandlerFunc(func(daemonapi.GetMapParams) middleware.Responder { return middleware.NotImplemented(apiNotSupported) }),
		GetMapNameHandler:       daemonapi.GetMapNameHandlerFunc(func(daemonapi.GetMapNameParams) middleware.Responder { return middleware.NotImplemented(apiNotSupported) }),
		GetMapNameEventsHandler: daemonapi.GetMapNameEventsHandlerFunc(func(daemonapi.GetMapNameEventsParams) middleware.Responder { return middleware.NotImplemented(apiNotSupported) }),
		GetNodeIdsHandler:       daemonapi.GetNodeIdsHandlerFunc(func(daemonapi.GetNodeIdsParams) middleware.Responder { return middleware.NotImplemented(apiNotSupported) }),

		GetPrefilterHandler:    prefilterapi.GetPrefilterHandlerFunc(func(prefilterapi.GetPrefilterParams) middleware.Responder { return middleware.NotImplemented(apiNotSupported) }),
		PatchPrefilterHandler:  prefilterapi.PatchPrefilterHandlerFunc(func(prefilterapi.PatchPrefilterParams) middleware.Responder { return middleware.NotImplemented(apiNotSupported) }),
		DeletePrefilterHandler: prefilterapi.DeletePrefilterHandlerFunc(func(prefilterapi.DeletePrefilterParams) middleware.Responder { return middleware.NotImplemented(apiNotSupported) }),
	}
}
