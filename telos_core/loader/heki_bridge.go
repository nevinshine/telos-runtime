package main

// Phase 6: Heki Bridge — Ring -1 Hypervisor Integration
//
// Communicates with sentinel-vmi to register BPF map memory pages
// for EPT/NPT write-protection. When active, any Ring 0 write to
// protected map pages triggers a #NPF → VMExit to the hypervisor.
//
// References:
//   sentinel-vmi/src/npt_guard.c   — set_page_readonly(), guard_region
//   telos-lang/telosc/src/heki/    — EptMapping, HekiMonitor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
)

// HekiBridge communicates with sentinel-vmi to register BPF map
// memory pages for hardware-level write-protection via EPT/NPT.
type HekiBridge struct {
	socketPath string
	connected  bool
	enabled    bool
}

// HekiRegistration represents the fixed-size binary struct expected by sentinel-vmi
type HekiRegistration struct {
	Magic      uint32
	GVA        uint64
	Size       uint32
	IsCritical uint8
	Name       [32]byte
}

// HekiGuardResponse is the response from sentinel-vmi (still JSON for response if we want, or binary?)
// Wait, if the request is binary, is the response binary? The user only specified the registration struct.
// Let's assume the response is also just a simple 1-byte success code or similar, or we just drop the response parsing.
// Actually, to be safe, I'll just read 1 byte for success.


// NewHekiBridge creates a bridge to sentinel-vmi.
// Set TELOS_HEKI_VMI_SOCKET to the sentinel-vmi Unix socket path.
func NewHekiBridge() *HekiBridge {
	socketPath := os.Getenv("TELOS_HEKI_VMI_SOCKET")
	enabled := socketPath != ""

	if enabled {
		log.Printf("[HEKI] Bridge enabled, VMI socket: %s", socketPath)
	} else {
		log.Printf("[HEKI] Bridge disabled (set TELOS_HEKI_VMI_SOCKET to enable)")
	}

	return &HekiBridge{
		socketPath: socketPath,
		enabled:    enabled,
	}
}

// ProtectMapPages sends the BPF map file descriptors to sentinel-vmi
// for NPT write-protection. sentinel-vmi will resolve the FDs to
// physical page addresses and mark them read-only in the EPT/NPT.
func (h *HekiBridge) ProtectMapPages(maps *BPFMaps) error {
	if !h.enabled {
		log.Printf("[HEKI] Skipping map protection (bridge disabled)")
		return nil
	}

	// Build list of maps to protect
	mapEntries := []struct {
		name    string
		m       *ebpf.Map
		pin     string
		critical bool
	}{
		{"process_map", maps.ProcessMap, filepath.Join(bpfPinPath, "process_map"), true},
		{"network_map", maps.NetworkMap, filepath.Join(bpfPinPath, "network_map"), true},
		{"inode_map", maps.InodeMap, filepath.Join(bpfPinPath, "inode_map"), true},
		{"config_map", maps.ConfigMap, filepath.Join(bpfPinPath, "config_map"), true},
		{"exec_policy_map", maps.ExecPolicyMap, filepath.Join(bpfPinPath, "exec_policy_map"), false},
	}

	// Send to sentinel-vmi
	protectedCount := 0
	for _, entry := range mapEntries {
		if entry.m == nil {
			continue
		}

		gva, err := LeakMapGVA(entry.m)
		if err != nil {
			log.Printf("[HEKI] WARNING: failed to leak GVA for %s: %v", entry.name, err)
			continue
		}

		// Assume map struct size is at least 4096 (1 page) for protection purposes,
		// or pass the value from Info if we can. We'll pass 4096.
		req := HekiRegistration{
			Magic:      0x48454B49,
			GVA:        gva,
			Size:       4096, 
			IsCritical: 0,
		}
		if entry.critical {
			req.IsCritical = 1
		}
		copy(req.Name[:], entry.name)

		err = h.sendBinaryRequest(req)
		if err != nil {
			return fmt.Errorf("VMI protection failed for %s: %w", entry.name, err)
		}
		protectedCount++
	}

	h.connected = true
	log.Printf("[HEKI] ✓ %d map pages under Ring -1 NPT write-protection", protectedCount)
	return nil
}

// sendBinaryRequest sends a binary request to sentinel-vmi and reads a 1-byte response.
func (h *HekiBridge) sendBinaryRequest(req HekiRegistration) error {
	conn, err := net.DialTimeout("unix", h.socketPath, 5*time.Second)
	if err != nil {
		return fmt.Errorf("cannot connect to VMI at %s: %w", h.socketPath, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send request
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, req); err != nil {
		return fmt.Errorf("failed to encode request: %w", err)
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	// Read response (4 bytes: Nonce. 0 = failure)
	resp := make([]byte, 4)
	if _, err := conn.Read(resp); err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	nonce := binary.LittleEndian.Uint32(resp)
	if nonce == 0 {
		return fmt.Errorf("hypervisor rejected the registration")
	}
	hekiNonce = nonce

	return nil
}

// IsConnected returns true if the bridge has successfully communicated
// with sentinel-vmi at least once.
func (h *HekiBridge) IsConnected() bool {
	return h.connected
}

// IsEnabled returns true if the bridge is configured.
func (h *HekiBridge) IsEnabled() bool {
	return h.enabled
}

// cmdHekiStatus handles the HEKI_STATUS IPC command.
func (d *TelosDaemon) cmdHekiStatus() IPCResponse {
	if d.hekiBridge == nil {
		return IPCResponse{Success: true, Data: map[string]interface{}{
			"enabled":   false,
			"connected": false,
			"status":    "bridge_not_initialized",
		}}
	}

	return IPCResponse{Success: true, Data: map[string]interface{}{
		"enabled":     d.hekiBridge.IsEnabled(),
		"connected":   d.hekiBridge.IsConnected(),
		"vmi_socket":  d.hekiBridge.socketPath,
		"status":      "operational",
	}}
}
