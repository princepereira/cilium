// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package socketlb

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/maps/registry"
)

const (
	Subsystem    = "socketlb"
	Connect4     = "cil_sock4_connect"
	SendMsg4     = "cil_sock4_sendmsg"
	RecvMsg4     = "cil_sock4_recvmsg"
	GetPeerName4 = "cil_sock4_getpeername"
	PostBind4    = "cil_sock4_post_bind"
	PreBind4     = "cil_sock4_pre_bind"
	Connect6     = "cil_sock6_connect"
	SendMsg6     = "cil_sock6_sendmsg"
	RecvMsg6     = "cil_sock6_recvmsg"
	GetPeerName6 = "cil_sock6_getpeername"
	PostBind6    = "cil_sock6_post_bind"
	PreBind6     = "cil_sock6_pre_bind"
	SockRelease  = "cil_sock_release"
)

func Enable(*slog.Logger, *registry.MapRegistry, sysctl.Sysctl, *config.Config) error { return nil }
func Disable(*slog.Logger) error                                                       { return nil }
