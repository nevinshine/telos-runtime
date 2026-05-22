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
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
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

// HekiGuardRequest is the wire format for registering a protected region
// with sentinel-vmi. Maps to npt_guard.c's add_guard_region().
type HekiGuardRequest struct {
	Command  string           `json:"command"`
	Regions  []HekiGuardPage  `json:"regions"`
}

// HekiGuardPage represents a single memory page to protect.
// Maps to sentinel-vmi's guard_region struct.
type HekiGuardPage struct {
	Name         string `json:"name"`          // e.g., "telos_process_map"
	MapFD        int    `json:"map_fd"`        // BPF map file descriptor
	PinPath      string `json:"pin_path"`      // e.g., "/sys/fs/bpf/telos/process_map"
	Critical     bool   `json:"critical"`      // If true, modification = panic guest
	AccessRights uint8  `json:"access_rights"` // 0b101 = Read+Execute, no Write
}

// HekiGuardResponse is the response from sentinel-vmi.
type HekiGuardResponse struct {
	Success        bool   `json:"success"`
	Error          string `json:"error,omitempty"`
	ProtectedPages int    `json:"protected_pages"`
}

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
	regions := []HekiGuardPage{}

	mapEntries := []struct {
		name    string
		m       *ebpf.Map
		pin     string
		critical bool
	}{
		{"process_map", maps.ProcessMap, bpfPinPath + "/process_map", true},
		{"network_map", maps.NetworkMap, bpfPinPath + "/network_map", true},
		{"inode_map", maps.InodeMap, bpfPinPath + "/inode_map", true},
		{"config_map", maps.ConfigMap, bpfPinPath + "/config_map", true},
		{"exec_policy_map", maps.ExecPolicyMap, bpfPinPath + "/exec_policy_map", false},
	}

	for _, entry := range mapEntries {
		if entry.m == nil {
			continue
		}
		info, err := entry.m.Info()
		if err != nil {
			log.Printf("[HEKI] WARNING: cannot get info for %s: %v", entry.name, err)
			continue
		}
		id, _ := info.ID()
		regions = append(regions, HekiGuardPage{
			Name:         entry.name,
			MapFD:        int(id),
			PinPath:      entry.pin,
			Critical:     entry.critical,
			AccessRights: 0b101, // Read + Execute, no Write
		})
	}

	if len(regions) == 0 {
		return fmt.Errorf("no maps to protect")
	}

	// Send to sentinel-vmi
	req := HekiGuardRequest{
		Command: "PROTECT_PAGES",
		Regions: regions,
	}

	resp, err := h.sendRequest(req)
	if err != nil {
		return fmt.Errorf("VMI request failed: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("VMI protection failed: %s", resp.Error)
	}

	h.connected = true
	log.Printf("[HEKI] ✓ %d map pages under Ring -1 NPT write-protection", resp.ProtectedPages)
	return nil
}

// sendRequest sends a JSON request to sentinel-vmi and reads the response.
func (h *HekiBridge) sendRequest(req HekiGuardRequest) (*HekiGuardResponse, error) {
	conn, err := net.DialTimeout("unix", h.socketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to VMI at %s: %w", h.socketPath, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send request
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(req); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read response
	var resp HekiGuardResponse
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return &resp, nil
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
