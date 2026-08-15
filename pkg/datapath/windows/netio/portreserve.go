// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package netio

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Winsock port-reservation ioctl codes (mstcpip.h). These are
// _WSAIORW(IOC_VENDOR, n): IOC_INOUT (0xC0000000) | IOC_VENDOR (0x18000000) | n.
const (
	sioAcquirePortReservation = 0xC0000000 | 0x18000000 | 100 // 0xD8000064
	sioReleasePortReservation = 0xC0000000 | 0x18000000 | 101 // 0xD8000065
)

// PortRange mirrors INET_PORT_RANGE. StartPort is stored in network byte order,
// matching the Win32 API contract.
type PortRange struct {
	StartPort     uint16 // network byte order
	NumberOfPorts uint16
}

// portReservationInstance mirrors INET_PORT_RESERVATION_INSTANCE.
type portReservationInstance struct {
	Reservation PortRange
	Token       uint64 // INET_PORT_RESERVATION_TOKEN
}

// PortReservation is the result of a runtime port reservation.
type PortReservation struct {
	StartPort     uint16 // host byte order
	NumberOfPorts uint16
	Token         uint64
}

var (
	procCreatePersistentUdpPortReservation = modiphlpapi.NewProc("CreatePersistentUdpPortReservation")
	procDeletePersistentUdpPortReservation = modiphlpapi.NewProc("DeletePersistentUdpPortReservation")
)

// AcquirePortReservation reserves a contiguous block of numberOfPorts ports on
// the given socket via WSAIoctl(SIO_ACQUIRE_PORT_RESERVATION). Passing
// startPort=0 lets the system choose the block. It is used by the Windows agent
// for runtime port reservation.
//
// https://learn.microsoft.com/en-us/windows/win32/winsock/sio-acquire-port-reservation
func AcquirePortReservation(sock windows.Handle, startPort, numberOfPorts uint16) (PortReservation, error) {
	in := PortRange{
		StartPort:     hostToNetU16(startPort),
		NumberOfPorts: numberOfPorts,
	}
	var out portReservationInstance
	var bytesReturned uint32

	err := windows.WSAIoctl(
		sock,
		sioAcquirePortReservation,
		(*byte)(unsafe.Pointer(&in)), uint32(unsafe.Sizeof(in)),
		(*byte)(unsafe.Pointer(&out)), uint32(unsafe.Sizeof(out)),
		&bytesReturned,
		nil, 0,
	)
	if err != nil {
		return PortReservation{}, fmt.Errorf("SIO_ACQUIRE_PORT_RESERVATION: %w", err)
	}

	return PortReservation{
		StartPort:     netToHostU16(out.Reservation.StartPort),
		NumberOfPorts: out.Reservation.NumberOfPorts,
		Token:         out.Token,
	}, nil
}

// ReleasePortReservation releases a runtime port reservation previously acquired
// with AcquirePortReservation.
//
// https://learn.microsoft.com/en-us/windows/win32/winsock/sio-release-port-reservation
func ReleasePortReservation(sock windows.Handle, res PortReservation) error {
	in := PortRange{
		StartPort:     hostToNetU16(res.StartPort),
		NumberOfPorts: res.NumberOfPorts,
	}
	var bytesReturned uint32

	err := windows.WSAIoctl(
		sock,
		sioReleasePortReservation,
		(*byte)(unsafe.Pointer(&in)), uint32(unsafe.Sizeof(in)),
		nil, 0,
		&bytesReturned,
		nil, 0,
	)
	if err != nil {
		return fmt.Errorf("SIO_RELEASE_PORT_RESERVATION: %w", err)
	}
	return nil
}

// CreatePersistentUdpPortReservation reserves a persistent block of UDP ports.
// startPort is in host byte order (0 lets the system choose). It wraps
// CreatePersistentUdpPortReservation from iphlpapi.
//
// https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-createpersistentudpportreservation
func CreatePersistentUdpPortReservation(startPort, numberOfPorts uint16) (token uint64, err error) {
	ret, _, _ := procCreatePersistentUdpPortReservation.Call(
		uintptr(hostToNetU16(startPort)),
		uintptr(numberOfPorts),
		uintptr(unsafe.Pointer(&token)),
	)
	if ret != 0 {
		return 0, fmt.Errorf("CreatePersistentUdpPortReservation: %w", windows.Errno(ret))
	}
	return token, nil
}

// DeletePersistentUdpPortReservation deletes a persistent UDP port reservation.
// startPort is in host byte order.
//
// https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-deletepersistentudpportreservation
func DeletePersistentUdpPortReservation(startPort, numberOfPorts uint16) error {
	ret, _, _ := procDeletePersistentUdpPortReservation.Call(
		uintptr(hostToNetU16(startPort)),
		uintptr(numberOfPorts),
	)
	if ret != 0 {
		return fmt.Errorf("DeletePersistentUdpPortReservation: %w", windows.Errno(ret))
	}
	return nil
}

func hostToNetU16(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

func netToHostU16(v uint16) uint16 {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], v)
	return binary.BigEndian.Uint16(b[:])
}
