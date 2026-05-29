//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// preInstallHook performs ownership validation and acquires an exclusive flock on the
// target PID file (creating it if necessary). It returns a cleanup function that
// releases the lock and closes the file, or an error.
func preInstallHook(_tmpName, path string) (func() error, error) {
	// Reject symlink targets
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("pidfile target is a symlink")
		}
		// Ownership check when possible
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			uid := int(st.Uid)
			if uid != os.Geteuid() && os.Geteuid() != 0 {
				return nil, fmt.Errorf("pidfile owned by different user")
			}
		}
	}

	// Open (or create) the target file so we can lock it
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}

	// Acquire exclusive lock
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}

	cleanup := func() error {
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	}

	return cleanup, nil
}
