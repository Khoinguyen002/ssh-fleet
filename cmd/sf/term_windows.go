//go:build windows

package main

import (
	"os"
	"syscall"
)

func termSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

func terminalSize(_ *os.File) (cols, rows int) {
	return 0, 0
}

func enterRawTerminal(_ *os.File) (func(), error) {
	return func() {}, nil
}
