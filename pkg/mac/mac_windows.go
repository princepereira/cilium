// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package mac

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/cilium/cilium/pkg/datapath/windows/netio"
)

// netClassKey is the registry path holding per-adapter configuration under the
// network adapter setup class GUID. Each numeric subkey (0000, 0001, ...)
// describes one adapter; the NetCfgInstanceId value holds the adapter's
// interface GUID.
const netClassKey = `SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}`

var (
	modAdvapi32       = windows.NewLazySystemDLL("advapi32.dll")
	procRegSetValueEx = modAdvapi32.NewProc("RegSetValueExW")
)

// ReplaceMacAddressWithLinkName replaces the MAC address of the given link.
//
// On Windows there is no direct netlink-style "set hardware address" call. The
// administratively assigned MAC is stored in the adapter's NetworkAddress
// registry value (12 uppercase hex digits, no separators). The change takes
// effect the next time the adapter is restarted (disable/enable).
//
// Matching Linux behaviour, a missing interface is treated as success (nil).
func ReplaceMacAddressWithLinkName(ifName, macAddress string) error {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		// Interface not found: treat as no-op, like the Linux implementation.
		return nil
	}

	hw, err := net.ParseMAC(macAddress)
	if err != nil {
		return err
	}

	guid, err := interfaceGUID(uint32(iface.Index))
	if err != nil {
		return err
	}

	subkey, err := findAdapterSubkey(guid)
	if err != nil {
		return err
	}

	path, err := windows.UTF16PtrFromString(netClassKey + `\` + subkey)
	if err != nil {
		return err
	}
	var h windows.Handle
	if err := windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, path, 0, windows.KEY_SET_VALUE, &h); err != nil {
		return fmt.Errorf("open adapter registry key %q: %w", subkey, err)
	}
	defer windows.RegCloseKey(h)

	if err := regSetString(h, "NetworkAddress", macToRegistry(hw)); err != nil {
		return fmt.Errorf("set NetworkAddress for %q: %w", ifName, err)
	}
	return nil
}

// interfaceGUID resolves the interface GUID (which equals the adapter's
// NetCfgInstanceId) from an interface index.
func interfaceGUID(index uint32) (string, error) {
	luid, err := netio.ConvertInterfaceIndexToLuid(index)
	if err != nil {
		return "", err
	}
	guid, err := netio.ConvertInterfaceLuidToGuid(luid)
	if err != nil {
		return "", err
	}
	return guidString(guid.Data1, guid.Data2, guid.Data3, guid.Data4), nil
}

// findAdapterSubkey returns the numeric subkey (e.g. "0007") under netClassKey
// whose NetCfgInstanceId matches the given interface GUID.
func findAdapterSubkey(guid string) (string, error) {
	path, err := windows.UTF16PtrFromString(netClassKey)
	if err != nil {
		return "", err
	}
	var root windows.Handle
	if err := windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, path, 0,
		windows.KEY_ENUMERATE_SUB_KEYS, &root); err != nil {
		return "", fmt.Errorf("open network class key: %w", err)
	}
	defer windows.RegCloseKey(root)

	for i := uint32(0); ; i++ {
		name, err := enumSubKey(root, i)
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("enumerate adapter subkeys: %w", err)
		}

		id, err := readAdapterInstanceID(name)
		if err != nil {
			continue
		}
		if strings.EqualFold(id, guid) {
			return name, nil
		}
	}
	return "", errors.New("no adapter registry key matches interface GUID " + guid)
}

// enumSubKey returns the name of the subkey at the given index.
func enumSubKey(key windows.Handle, index uint32) (string, error) {
	buf := make([]uint16, 256)
	n := uint32(len(buf))
	if err := windows.RegEnumKeyEx(key, index, &buf[0], &n, nil, nil, nil, nil); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// readAdapterInstanceID reads the NetCfgInstanceId value from a numeric adapter
// subkey.
func readAdapterInstanceID(subkey string) (string, error) {
	path, err := windows.UTF16PtrFromString(netClassKey + `\` + subkey)
	if err != nil {
		return "", err
	}
	var h windows.Handle
	if err := windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, path, 0, windows.KEY_QUERY_VALUE, &h); err != nil {
		return "", err
	}
	defer windows.RegCloseKey(h)
	return regQueryString(h, "NetCfgInstanceId")
}

// regQueryString reads a REG_SZ value from an open registry key.
func regQueryString(key windows.Handle, name string) (string, error) {
	valName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	var size uint32
	if err := windows.RegQueryValueEx(key, valName, nil, nil, nil, &size); err != nil {
		return "", err
	}
	if size == 0 {
		return "", nil
	}
	buf := make([]byte, size)
	if err := windows.RegQueryValueEx(key, valName, nil, nil, &buf[0], &size); err != nil {
		return "", err
	}
	u16 := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[0])), size/2)
	return windows.UTF16ToString(u16), nil
}

// regSetString writes a REG_SZ value to an open registry key via advapi32.
func regSetString(key windows.Handle, name, value string) error {
	valName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	data, err := windows.UTF16FromString(value)
	if err != nil {
		return err
	}
	dataBytes := uint32(len(data) * 2)
	ret, _, _ := procRegSetValueEx.Call(
		uintptr(key),
		uintptr(unsafe.Pointer(valName)),
		0,
		uintptr(windows.REG_SZ),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(dataBytes),
	)
	if ret != 0 {
		return windows.Errno(ret)
	}
	return nil
}

// guidString formats a GUID in the registry string form
// "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}".
func guidString(d1 uint32, d2, d3 uint16, d4 [8]byte) string {
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		d1, d2, d3,
		d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7])
}

// macToRegistry renders a hardware address as the 12 uppercase hex digits
// (no separators) expected by the NetworkAddress registry value.
func macToRegistry(hw net.HardwareAddr) string {
	var b strings.Builder
	for _, o := range hw {
		fmt.Fprintf(&b, "%02X", o)
	}
	return b.String()
}
