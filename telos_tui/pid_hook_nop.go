//go:build windows

package main

// preInstallHook no-op stub for platforms that don't implement Unix locking/ownership checks.
func preInstallHook(_tmpName, _path string) (func() error, error) {
	return nil, nil
}
