//go:build windows

package updater

import (
	"os"
	"os/exec"
)

// ReExec starts the updated binary and exits the current process on Windows.
func ReExec(exePath string) error {
	cmd := exec.Command(exePath, os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	os.Exit(0)
	return nil
}
