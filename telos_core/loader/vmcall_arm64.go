//go:build arm64

package main

// hekiNonce is established during the initial IPC registration with sentinel-vmi
var hekiNonce uint32 = 0

// HekiIntentUnlock for ARM64 architectures.
// The CPUID instruction does not exist on ARM. Instead, the Heki Drawbridge trap
// is handled natively via Stage-2 Data Aborts (synchronous EL2 exception).
// Therefore, this stub intentionally performs no action.
func HekiIntentUnlock() {
	// MOCK VMEXIT is skipped. ARM64 bypasses CPUID intercepts entirely.
}
