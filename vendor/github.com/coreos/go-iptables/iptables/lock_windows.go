// Copyright 2015 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build windows

package iptables

import (
	"sync"
	"syscall"
)

const (
	xtablesLockFilePath = "xtables.lock"

	defaultFilePerm = 0600
)

type Unlocker interface {
	Unlock() error
}

type nopUnlocker struct{}

func (nopUnlocker) Unlock() error { return nil }

// fileLock mirrors the Linux xtables file lock. iptables is not available on
// Windows, so locking is a no-op here. The fd field is typed as
// syscall.Handle to remain compatible with syscall.Close on Windows.
type fileLock struct {
	mu sync.Mutex
	fd syscall.Handle
}

// tryLock is a no-op on Windows and always succeeds.
func (l *fileLock) tryLock() (Unlocker, error) {
	return nopUnlocker{}, nil
}

// Unlock is a no-op on Windows.
func (l *fileLock) Unlock() error { return nil }

// newXtablesFileLock returns a no-op lock on Windows.
func newXtablesFileLock() (*fileLock, error) {
	return &fileLock{fd: syscall.InvalidHandle}, nil
}
