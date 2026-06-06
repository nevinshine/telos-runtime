//go:build amd64 && !cgo

package main

// Fallback definitions for environments where cgo is disabled.
// These provide harmless no-op implementations so the loader compiles
// on systems without a C compiler (CI windows runners, etc.).

import (
	"encoding/binary"
	"net"
	"os"
)

// hekiNonce is established during the initial IPC registration with sentinel-vmi
var hekiNonce uint32 = 0

// HekiIntentUnlock no-op fallback when cgo is unavailable; this prevents
// undefined symbol errors on platforms/builds without cgo. In environments
// that support the real CPUID/VMEXIT mechanism, the cgo-enabled file will
// provide the active implementation.
func HekiIntentUnlock() {
	if hekiNonce != 0 {
		// Attempt a best-effort MOCK notification via the sentinel UNIX socket
		socketPath := os.Getenv("TELOS_HEKI_VMI_SOCKET")
		if socketPath == "" {
			return
		}
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 49)
		binary.LittleEndian.PutUint32(buf[0:4], 0x4D4F434B) // "MOCK"
		binary.LittleEndian.PutUint32(buf[4:8], hekiNonce)
		conn.Write(buf)
		ack := make([]byte, 4)
		conn.Read(ack)
	}
}
