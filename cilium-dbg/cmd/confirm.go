// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import "fmt"

// force is the shared "-f/--force" flag target used by several cleanup
// subcommands to skip confirmation prompts.
var force bool

func confirmCleanup() bool {
	fmt.Printf("The command is non-revertible, do you want to continue [y/N]?\n")
	var res string
	fmt.Scanln(&res)
	return res == "y"
}
