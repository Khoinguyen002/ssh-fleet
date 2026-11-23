//go:build !windows

package updater

import (
	"os"
	"syscall"
)

// ReExec atomically replaces the current process with the updated binary.
func ReExec(exePath string) error {
	return syscall.Exec(exePath, os.Args, os.Environ())
}
