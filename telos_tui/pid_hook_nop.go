//go:build windows

package main

// preInstallHook no-op stub for platforms that don't implement Unix locking/ownership checks.
func preInstallHook(_, _ string) (func() error, error) {
	return nil, nil
}
