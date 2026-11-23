//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

func termSignals() []os.Signal {
	return []os.Signal{syscall.SIGTERM, syscall.SIGHUP}
}

func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

func terminalSize(f *os.File) (cols, rows int) {
	if !isTerminal(f) {
		return 0, 0
	}
	cmd := exec.Command("stty", "size")
	cmd.Stdin = f
	out, err := cmd.Output()
	if err != nil {
		return 0, 0
	}
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d %d", &rows, &cols); err != nil {
		return 0, 0
	}
	return cols, rows
}

func enterRawTerminal(f *os.File) (func(), error) {
	saveCmd := exec.Command("stty", "-g")
	saveCmd.Stdin = f
	out, err := saveCmd.Output()
	if err != nil {
		return func() {}, err
	}
	saved := strings.TrimSpace(string(out))

	rawCmd := exec.Command("stty", "raw", "-echo")
	rawCmd.Stdin = f
	if err := rawCmd.Run(); err != nil {
		return func() {}, err
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			if saved == "" {
				return
			}
			rest := exec.Command("stty", saved)
			rest.Stdin = f
			_ = rest.Run()
		})
	}, nil
}
