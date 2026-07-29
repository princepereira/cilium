// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package envoy

// accessLogSocketNetwork is the AF_UNIX socket type used for the Envoy access
// log listener. Windows AF_UNIX only supports stream sockets (SOCK_STREAM), so
// a plain "unix" socket is used. Envoy itself does not run on these platforms,
// so message-boundary semantics are not required here.
const accessLogSocketNetwork = "unix"
