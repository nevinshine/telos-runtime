//go:build amd64

package main

/*
#include <stdint.h>
void heki_intent_unlock(uint32_t nonce) {
    uint32_t magic = 0x48454B49; // "HEKI"
    uint32_t eax = magic;
    uint32_t ecx = nonce;
    uint32_t ebx = 0;
    uint32_t edx = 0;

    // Execute CPUID to trigger VMEXIT.
    // KVM will intercept this and sentinel-vmi will catch the KVMI_EVENT_CPUID.
    asm volatile(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(magic), "c"(nonce)
        : "memory"
    );
}
*/
import "C"
import (
	"encoding/binary"
	"net"
	"os"
)

// hekiNonce is established during the initial IPC registration with sentinel-vmi
var hekiNonce uint32 = 0

// HekiIntentUnlock executes an authenticated CPUID instruction to signal
// to the sentinel-vmi hypervisor that the Go daemon intends to write
// to a protected map. The hypervisor will authorize the current vCPU's CR3.
func HekiIntentUnlock() {
	if hekiNonce != 0 {
		C.heki_intent_unlock(C.uint32_t(hekiNonce))

		// MOCK VMEXIT for demonstration: Send CPUID intent via IPC
		// In a real environment, KVM intercepts the CPUID assembly above!
		socketPath := os.Getenv("TELOS_HEKI_VMI_SOCKET")
		conn, err := net.Dial("unix", socketPath)
		if err == nil {
			defer conn.Close()
			buf := make([]byte, 49)                             // Match heki_registration size EXACTLY (49 bytes)
			binary.LittleEndian.PutUint32(buf[0:4], 0x4D4F434B) // "MOCK"
			binary.LittleEndian.PutUint32(buf[4:8], hekiNonce)
			conn.Write(buf)

			ack := make([]byte, 4)
			conn.Read(ack)
		}
	}
}
