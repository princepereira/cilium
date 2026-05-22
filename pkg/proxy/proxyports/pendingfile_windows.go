// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build windows

package proxyports

import "os"

type pendingFile struct {
	*os.File
	path string
}

func newPendingFile(path string) (*pendingFile, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &pendingFile{File: f, path: path}, nil
}

func (p *pendingFile) Cleanup() {
	_ = p.Close()
}

func (p *pendingFile) CloseAtomicallyReplace() error {
	return p.Close()
}
