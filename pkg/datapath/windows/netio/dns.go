// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package netio

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DNS_INTERFACE_SETTINGS version and flag values (windns.h).
const (
	DnsInterfaceSettingsVersion1 = 1

	DnsSettingIPv6                = 0x0001
	DnsSettingNameServer          = 0x0002
	DnsSettingSearchList          = 0x0004
	DnsSettingRegistrationEnabled = 0x0008
	DnsSettingRegisterAdapterName = 0x0010
	DnsSettingDomain              = 0x0020
	DnsSettingHostname            = 0x0040
	DnsSettingEnableLLMNR         = 0x0080
	DnsSettingQueryAdapterName    = 0x0100
	DnsSettingProfileNameServer   = 0x0200
)

// DnsInterfaceSettings mirrors DNS_INTERFACE_SETTINGS (version 1) from windns.h.
// String fields are UTF-16 pointers owned by the API after a Get and must be
// released with FreeInterfaceDnsSettings.
//
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-dns_interface_settings
type DnsInterfaceSettings struct {
	Version             uint32
	_                   uint32 // padding to 8-byte-align Flags
	Flags               uint64
	Domain              *uint16
	NameServer          *uint16
	SearchList          *uint16
	RegistrationEnabled uint32
	RegisterAdapterName uint32
	EnableLLMNR         uint32
	QueryAdapterName    uint32
	ProfileNameServer   *uint16
}

// DomainString returns the Domain field as a Go string.
func (s *DnsInterfaceSettings) DomainString() string { return utf16PtrToString(s.Domain) }

// NameServerString returns the NameServer field as a Go string.
func (s *DnsInterfaceSettings) NameServerString() string { return utf16PtrToString(s.NameServer) }

// SearchListString returns the SearchList field as a Go string.
func (s *DnsInterfaceSettings) SearchListString() string { return utf16PtrToString(s.SearchList) }

var (
	procGetInterfaceDnsSettings  = modiphlpapi.NewProc("GetInterfaceDnsSettings")
	procSetInterfaceDnsSettings  = modiphlpapi.NewProc("SetInterfaceDnsSettings")
	procFreeInterfaceDnsSettings = modiphlpapi.NewProc("FreeInterfaceDnsSettings")
)

// GetInterfaceDnsSettings reads the DNS settings for the interface identified by
// guid. The requested fields are selected via flags (DnsSetting* constants). The
// returned settings must be released with FreeInterfaceDnsSettings.
//
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getinterfacednssettings
func GetInterfaceDnsSettings(guid windows.GUID, flags uint64) (*DnsInterfaceSettings, error) {
	settings := &DnsInterfaceSettings{
		Version: DnsInterfaceSettingsVersion1,
		Flags:   flags,
	}
	// A GUID is passed by value in the C signature; on x64 a 16-byte struct is
	// passed by reference, so the first argument is a pointer to the GUID.
	ret, _, _ := procGetInterfaceDnsSettings.Call(
		uintptr(unsafe.Pointer(&guid)),
		uintptr(unsafe.Pointer(settings)),
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetInterfaceDnsSettings: %w", windows.Errno(ret))
	}
	return settings, nil
}

// SetInterfaceDnsSettings applies DNS settings to the interface identified by
// guid.
//
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setinterfacednssettings
func SetInterfaceDnsSettings(guid windows.GUID, settings *DnsInterfaceSettings) error {
	settings.Version = DnsInterfaceSettingsVersion1
	ret, _, _ := procSetInterfaceDnsSettings.Call(
		uintptr(unsafe.Pointer(&guid)),
		uintptr(unsafe.Pointer(settings)),
	)
	if ret != 0 {
		return fmt.Errorf("SetInterfaceDnsSettings: %w", windows.Errno(ret))
	}
	return nil
}

// FreeInterfaceDnsSettings releases the string buffers allocated by
// GetInterfaceDnsSettings.
//
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-freeinterfacednssettings
func FreeInterfaceDnsSettings(settings *DnsInterfaceSettings) {
	if settings == nil {
		return
	}
	procFreeInterfaceDnsSettings.Call(uintptr(unsafe.Pointer(settings)))
}

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	return windows.UTF16PtrToString(p)
}
