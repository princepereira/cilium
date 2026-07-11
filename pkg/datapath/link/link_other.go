// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package link

import (
	"context"
	"fmt"
	"strconv"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/mac"
)

var errUnsupportedOp = fmt.Errorf("link operations are not supported on this platform")

// DeleteByName deletes the interface with the name ifName.
func DeleteByName(ifName string) error {
	return errUnsupportedOp
}

// Rename renames a network link.
func Rename(curName, newName string) error {
	return errUnsupportedOp
}

// AddAltName sets an alternative name for a link.
func AddAltName(linkName, altName string) error {
	return errUnsupportedOp
}

func GetHardwareAddr(ifName string) (mac.MAC, error) {
	return nil, errUnsupportedOp
}

func GetIfIndex(ifName string) (uint32, error) {
	return 0, errUnsupportedOp
}

func GetIfBufferMargins(ifName string) (uint16, uint16, error) {
	return 0, 0, errUnsupportedOp
}

type LinkCache struct {
	mu          lock.RWMutex
	indexToName map[int]string
}

var Cell = cell.Module(
	"link-cache",
	"Provides a cache of link names to ifindex mappings",

	cell.Provide(NewLinkCache),
)

func NewLinkCache() *LinkCache {
	return &LinkCache{
		indexToName: make(map[int]string),
	}
}

func (c *LinkCache) SyncCache(_ context.Context) error {
	return nil
}

func (c *LinkCache) lookupName(ifIndex int) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	name, ok := c.indexToName[ifIndex]
	return name, ok
}

// GetIfNameCached returns the name of an interface (if it exists) by looking
// it up in a regularly updated cache. The return result is the same as a map
// lookup, ie nil, false if there is no entry cached for this ifindex.
func (c *LinkCache) GetIfNameCached(ifIndex int) (string, bool) {
	return c.lookupName(ifIndex)
}

// Name returns the name of a link by looking up the 'LinkCache', or returns a
// string containing the ifindex on cache miss.
func (c *LinkCache) Name(ifIndex uint32) string {
	if name, ok := c.lookupName(int(ifIndex)); ok {
		return name
	}
	return strconv.Itoa(int(ifIndex))
}
