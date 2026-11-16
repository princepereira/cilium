// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package netio

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// NotificationType mirrors MIB_NOTIFICATION_TYPE from netioapi.h.
type NotificationType uint32

const (
	// NotificationParameter indicates a parameter of an existing object changed.
	NotificationParameter NotificationType = 0
	// NotificationAdd indicates a new object was added.
	NotificationAdd NotificationType = 1
	// NotificationDelete indicates an object was deleted.
	NotificationDelete NotificationType = 2
	// NotificationInitial is delivered once when initialNotification is set.
	NotificationInitial NotificationType = 3
)

func (t NotificationType) String() string {
	switch t {
	case NotificationParameter:
		return "parameter"
	case NotificationAdd:
		return "add"
	case NotificationDelete:
		return "delete"
	case NotificationInitial:
		return "initial"
	default:
		return fmt.Sprintf("unknown(%d)", uint32(t))
	}
}

// AddressChangeHandler is invoked for every unicast IP address change. Note the
// callback runs on a system worker thread; handlers must be non-blocking and
// concurrency-safe. Row is only valid for the duration of the call.
type AddressChangeHandler func(row *windows.MibUnicastIpAddressRow, typ NotificationType)

// AddressChangeSubscription represents an active unicast address-change
// subscription. Call Close to unsubscribe.
type AddressChangeSubscription struct {
	handle   windows.Handle
	callback uintptr // retained to document the callback's lifetime
}

// SubscribeUnicastAddressChange registers handler to be called whenever a
// unicast IP address of the given family (windows.AF_INET, windows.AF_INET6 or
// windows.AF_UNSPEC for both) changes. If initial is true, the handler is
// invoked once immediately with NotificationInitial. It wraps
// NotifyUnicastIpAddressChange and is the Windows counterpart of
// netlink.AddrSubscribe.
//
// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyunicastipaddresschange
func SubscribeUnicastAddressChange(family uint16, initial bool, handler AddressChangeHandler) (*AddressChangeSubscription, error) {
	if handler == nil {
		return nil, fmt.Errorf("handler must not be nil")
	}

	callback := windows.NewCallback(func(_ uintptr, row *windows.MibUnicastIpAddressRow, notificationType uint32) uintptr {
		handler(row, NotificationType(notificationType))
		return 0
	})

	var handle windows.Handle
	if err := windows.NotifyUnicastIpAddressChange(family, callback, nil, initial, &handle); err != nil {
		return nil, fmt.Errorf("NotifyUnicastIpAddressChange: %w", err)
	}

	return &AddressChangeSubscription{handle: handle, callback: callback}, nil
}

// Close unsubscribes from address-change notifications. It wraps
// CancelMibChangeNotify2.
func (s *AddressChangeSubscription) Close() error {
	if s == nil || s.handle == 0 {
		return nil
	}
	if err := windows.CancelMibChangeNotify2(s.handle); err != nil {
		return fmt.Errorf("CancelMibChangeNotify2: %w", err)
	}
	s.handle = 0
	return nil
}
