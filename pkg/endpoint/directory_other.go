// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package endpoint

import (
	"fmt"
	"os"
)

// exchangeDirectories swaps tmpDir and origDir. Non-Linux platforms lack the
// atomic renameat2(RENAME_EXCHANGE) syscall, so this performs a best-effort,
// non-atomic three-way rename.
func exchangeDirectories(tmpDir, origDir string) error {
	backup := origDir + "_exchange_backup"

	if err := os.RemoveAll(backup); err != nil {
		return fmt.Errorf("failed to clear backup dir %s: %w", backup, err)
	}
	if err := os.Rename(origDir, backup); err != nil {
		return fmt.Errorf("failed to move %s to backup: %w", origDir, err)
	}
	if err := os.Rename(tmpDir, origDir); err != nil {
		// Attempt to restore the original directory on failure.
		_ = os.Rename(backup, origDir)
		return fmt.Errorf("failed to move %s to %s: %w", tmpDir, origDir, err)
	}
	if err := os.Rename(backup, tmpDir); err != nil {
		return fmt.Errorf("failed to move backup to %s: %w", tmpDir, err)
	}
	return nil
}
