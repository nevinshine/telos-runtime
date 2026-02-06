/*
 * Telos Core - eBPF Loader Daemon
 *
 * This daemon:
 *   1. Loads the compiled eBPF LSM program
 *   2. Pins maps to /sys/fs/bpf/telos/ for persistence
 *   3. Attaches LSM hooks to the kernel
 *   4. Listens on a Unix socket for commands from Cortex
 *   5. Updates BPF maps based on taint reports
 *
 * Usage:
 *   sudo ./telos_daemon [--socket /var/run/telos.sock] [--bpf-obj bin/bpf_lsm.o]
 */

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// === CONFIGURATION ===

const (
	defaultSocketPath = "/var/run/telos.sock"
	defaultBPFObj     = "bin/bpf_lsm.o"
	bpfPinPath        = "/sys/fs/bpf/telos"
)

// Taint levels (must match common_maps.h)
const (
	TaintClean    = 0
	TaintLow      = 1
	TaintMedium   = 2
	TaintHigh     = 3
	TaintCritical = 4
)

// === DATA STRUCTURES ===

// ProcessInfo matches the BPF struct process_info_t
type ProcessInfo struct {
	PID         uint32
	TaintLevel  uint32
	IsSandboxed uint32
	Comm        [16]byte
}

// Config matches the BPF struct config_t
type Config struct {
	MaxTaintForExec uint32
	MaxTaintForOpen uint32
	Enabled         uint32
}

// IPCCommand is the JSON command from Cortex
type IPCCommand struct {
	Command string                 `json:"command"`
	Data    map[string]interface{} `json:"data"`
}

// IPCResponse is the JSON response to Cortex
type IPCResponse struct {
	Success bool        `json:"success"`
	Error   string      `json:"error,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// === BPF OBJECTS ===

// Maps loaded from the BPF object
type BPFMaps struct {
	ProcessMap *ebpf.Map
	ConfigMap  *ebpf.Map
	Events     *ebpf.Map
}

// Links to LSM hooks
type BPFLinks struct {
	CheckExec link.Link
	CheckFile link.Link
	TaskAlloc link.Link
}

// === MAIN DAEMON ===

type TelosDaemon struct {
	socketPath string
	bpfObjPath string
	maps       *BPFMaps
	links      *BPFLinks
	listener   net.Listener
	done       chan struct{}
}

func NewTelosDaemon(socketPath, bpfObjPath string) *TelosDaemon {
	return &TelosDaemon{
		socketPath: socketPath,
		bpfObjPath: bpfObjPath,
		done:       make(chan struct{}),
	}
}

// Start loads BPF and starts the socket server
func (d *TelosDaemon) Start() error {
	// ANSI color codes
	const (
		Reset   = "\033[0m"
		Bold    = "\033[1m"
		Red     = "\033[31m"
		Green   = "\033[32m"
		Yellow  = "\033[33m"
		Blue    = "\033[34m"
		Magenta = "\033[35m"
		Cyan    = "\033[36m"
		Orange  = "\033[38;5;208m"
	)

	// Print colorful banner
	fmt.Println()
	fmt.Println(Orange + "  ████████╗███████╗██╗      ██████╗ ███████╗" + Reset)
	fmt.Println(Orange + "  ╚══██╔══╝██╔════╝██║     ██╔═══██╗██╔════╝" + Reset)
	fmt.Println(Orange + "     ██║   █████╗  ██║     ██║   ██║███████╗" + Reset)
	fmt.Println(Orange + "     ██║   ██╔══╝  ██║     ██║   ██║╚════██║" + Reset)
	fmt.Println(Orange + "     ██║   ███████╗███████╗╚██████╔╝███████║" + Reset)
	fmt.Println(Orange + "     ╚═╝   ╚══════╝╚══════╝ ╚═════╝ ╚══════╝" + Reset)
	fmt.Println()
	fmt.Println(Cyan + "           ╔═══════════════════════════════╗" + Reset)
	fmt.Println(Cyan + "           ║" + Bold + "    eBPF LSM SECURITY CORE     " + Reset + Cyan + "║" + Reset)
	fmt.Println(Cyan + "           ╚═══════════════════════════════╝" + Reset)
	fmt.Println()

	// Remove memory lock limits for BPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}
	log.Println("✓ Removed memory lock limits")

	// Create pin directory
	if err := os.MkdirAll(bpfPinPath, 0755); err != nil {
		return fmt.Errorf("failed to create BPF pin path: %w", err)
	}

	// Load eBPF program
	if err := d.loadBPF(); err != nil {
		return fmt.Errorf("failed to load BPF: %w", err)
	}
	log.Println("✓ eBPF program loaded and attached")

	// Initialize config
	if err := d.initConfig(); err != nil {
		return fmt.Errorf("failed to init config: %w", err)
	}
	log.Println("✓ Default config initialized")

	// Start Unix socket server
	if err := d.startSocketServer(); err != nil {
		return fmt.Errorf("failed to start socket server: %w", err)
	}
	log.Printf("✓ Listening on %s", d.socketPath)

	fmt.Println()
	fmt.Println(Green + "  ╔═══════════════════════════════════════════════════════╗" + Reset)
	fmt.Println(Green + "  ║" + Bold + "        TELOS CORE ONLINE - Enforcing Security         " + Reset + Green + "║" + Reset)
	fmt.Println(Green + "  ╚═══════════════════════════════════════════════════════╝" + Reset)
	fmt.Println()

	return nil
}

// loadBPF loads the compiled eBPF object and attaches hooks
func (d *TelosDaemon) loadBPF() error {
	// Load the pre-compiled BPF object
	spec, err := ebpf.LoadCollectionSpec(d.bpfObjPath)
	if err != nil {
		return fmt.Errorf("load collection spec: %w", err)
	}

	// Load into kernel
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new collection: %w", err)
	}

	// Store map references
	d.maps = &BPFMaps{
		ProcessMap: coll.Maps["process_map"],
		ConfigMap:  coll.Maps["config_map"],
		Events:     coll.Maps["events"],
	}

	// Pin maps for external access
	processMapPath := filepath.Join(bpfPinPath, "process_map")
	if err := d.maps.ProcessMap.Pin(processMapPath); err != nil {
		log.Printf("Warning: Failed to pin process_map: %v", err)
	}

	// Attach LSM hooks
	d.links = &BPFLinks{}

	// Attach bprm_check_security
	prog := coll.Programs["telos_check_exec"]
	if prog != nil {
		l, err := link.AttachLSM(link.LSMOptions{
			Program: prog,
		})
		if err != nil {
			return fmt.Errorf("attach check_exec: %w", err)
		}
		d.links.CheckExec = l
		log.Println("  → Attached lsm/bprm_check_security")
	}

	// Attach file_open
	prog = coll.Programs["telos_check_file"]
	if prog != nil {
		l, err := link.AttachLSM(link.LSMOptions{
			Program: prog,
		})
		if err != nil {
			log.Printf("Warning: Failed to attach check_file: %v", err)
		} else {
			d.links.CheckFile = l
			log.Println("  → Attached lsm/file_open")
		}
	}

	// Attach task_alloc
	prog = coll.Programs["telos_task_alloc"]
	if prog != nil {
		l, err := link.AttachLSM(link.LSMOptions{
			Program: prog,
		})
		if err != nil {
			log.Printf("Warning: Failed to attach task_alloc: %v", err)
		} else {
			d.links.TaskAlloc = l
			log.Println("  → Attached lsm/task_alloc")
		}
	}

	return nil
}

// initConfig sets default configuration
func (d *TelosDaemon) initConfig() error {
	config := Config{
		MaxTaintForExec: TaintMedium, // Block HIGH and above
		MaxTaintForOpen: TaintHigh,   // Block CRITICAL only for files
		Enabled:         1,           // Enforce mode
	}

	var key uint32 = 0
	return d.maps.ConfigMap.Put(key, config)
}

// startSocketServer starts the Unix domain socket listener
func (d *TelosDaemon) startSocketServer() error {
	// Remove existing socket
	os.Remove(d.socketPath)

	listener, err := net.Listen("unix", d.socketPath)
	if err != nil {
		return err
	}
	d.listener = listener

	// Set socket permissions
	os.Chmod(d.socketPath, 0660)

	// Accept connections in goroutine
	go d.acceptConnections()

	return nil
}

// acceptConnections handles incoming socket connections
func (d *TelosDaemon) acceptConnections() {
	for {
		conn, err := d.listener.Accept()
		if err != nil {
			select {
			case <-d.done:
				return
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}
		go d.handleConnection(conn)
	}
}

// handleConnection processes a single socket connection
func (d *TelosDaemon) handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)

	for {
		// Read JSON line
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return // Connection closed
		}

		// Parse command
		var cmd IPCCommand
		if err := json.Unmarshal(line, &cmd); err != nil {
			d.sendResponse(conn, IPCResponse{
				Success: false,
				Error:   "Invalid JSON: " + err.Error(),
			})
			continue
		}

		// Handle command
		resp := d.handleCommand(cmd)
		d.sendResponse(conn, resp)
	}
}

// handleCommand dispatches commands to handlers
func (d *TelosDaemon) handleCommand(cmd IPCCommand) IPCResponse {
	switch cmd.Command {
	case "PING":
		return IPCResponse{Success: true, Data: "pong"}

	case "UPDATE_TAINT":
		return d.cmdUpdateTaint(cmd.Data)

	case "CLEAR_TAINT":
		return d.cmdClearTaint(cmd.Data)

	case "REGISTER_AGENT":
		return d.cmdRegisterAgent(cmd.Data)

	case "GET_STATE":
		return d.cmdGetState()

	default:
		return IPCResponse{
			Success: false,
			Error:   "Unknown command: " + cmd.Command,
		}
	}
}

// cmdUpdateTaint updates taint level for a PID
func (d *TelosDaemon) cmdUpdateTaint(data map[string]interface{}) IPCResponse {
	pidFloat, ok := data["pid"].(float64)
	if !ok {
		return IPCResponse{Success: false, Error: "Missing or invalid 'pid'"}
	}
	pid := uint32(pidFloat)

	levelFloat, ok := data["taint_level"].(float64)
	if !ok {
		return IPCResponse{Success: false, Error: "Missing or invalid 'taint_level'"}
	}
	level := uint32(levelFloat)

	// Update or create entry
	info := ProcessInfo{
		PID:        pid,
		TaintLevel: level,
	}

	if err := d.maps.ProcessMap.Put(pid, info); err != nil {
		return IPCResponse{Success: false, Error: err.Error()}
	}

	log.Printf("[UPDATE] PID %d taint -> %d", pid, level)
	return IPCResponse{Success: true}
}

// cmdClearTaint removes a PID from the taint map
func (d *TelosDaemon) cmdClearTaint(data map[string]interface{}) IPCResponse {
	pidFloat, ok := data["pid"].(float64)
	if !ok {
		return IPCResponse{Success: false, Error: "Missing or invalid 'pid'"}
	}
	pid := uint32(pidFloat)

	if err := d.maps.ProcessMap.Delete(pid); err != nil {
		// Ignore "not found" errors
		log.Printf("[CLEAR] PID %d (was not tracked)", pid)
	} else {
		log.Printf("[CLEAR] PID %d taint cleared", pid)
	}

	return IPCResponse{Success: true}
}

// cmdRegisterAgent adds an agent to tracking
func (d *TelosDaemon) cmdRegisterAgent(data map[string]interface{}) IPCResponse {
	pidFloat, ok := data["pid"].(float64)
	if !ok {
		return IPCResponse{Success: false, Error: "Missing or invalid 'pid'"}
	}
	pid := uint32(pidFloat)

	comm, _ := data["comm"].(string)

	info := ProcessInfo{
		PID:        pid,
		TaintLevel: TaintClean,
	}

	// Copy comm name
	if comm != "" {
		copy(info.Comm[:], []byte(comm))
	}

	if err := d.maps.ProcessMap.Put(pid, info); err != nil {
		return IPCResponse{Success: false, Error: err.Error()}
	}

	log.Printf("[REGISTER] Agent PID %d (%s)", pid, comm)
	return IPCResponse{Success: true}
}

// cmdGetState returns current map state (for debugging)
func (d *TelosDaemon) cmdGetState() IPCResponse {
	state := make(map[string]interface{})
	processes := make(map[uint32]map[string]interface{})

	iter := d.maps.ProcessMap.Iterate()
	var key uint32
	var value ProcessInfo

	for iter.Next(&key, &value) {
		processes[key] = map[string]interface{}{
			"taint_level": value.TaintLevel,
			"sandboxed":   value.IsSandboxed,
		}
	}

	state["processes"] = processes
	state["count"] = len(processes)

	return IPCResponse{Success: true, Data: state}
}

// sendResponse writes a JSON response to the connection
func (d *TelosDaemon) sendResponse(conn net.Conn, resp IPCResponse) {
	data, _ := json.Marshal(resp)
	conn.Write(data)
	conn.Write([]byte("\n"))
}

// Stop gracefully shuts down the daemon
func (d *TelosDaemon) Stop() {
	log.Println("Shutting down Telos Core...")

	close(d.done)

	if d.listener != nil {
		d.listener.Close()
	}

	// Detach LSM hooks
	if d.links != nil {
		if d.links.CheckExec != nil {
			d.links.CheckExec.Close()
		}
		if d.links.CheckFile != nil {
			d.links.CheckFile.Close()
		}
		if d.links.TaskAlloc != nil {
			d.links.TaskAlloc.Close()
		}
	}

	// Clean up socket
	os.Remove(d.socketPath)

	log.Println("TELOS CORE offline")
}

// === MAIN ===

func main() {
	socketPath := flag.String("socket", defaultSocketPath, "Unix socket path")
	bpfObj := flag.String("bpf-obj", defaultBPFObj, "Path to compiled BPF object")
	flag.Parse()

	// Check for root
	if os.Geteuid() != 0 {
		log.Fatal("Telos Core requires root privileges to load eBPF")
	}

	daemon := NewTelosDaemon(*socketPath, *bpfObj)

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		daemon.Stop()
		os.Exit(0)
	}()

	// Start daemon
	if err := daemon.Start(); err != nil {
		log.Fatalf("Failed to start: %v", err)
	}

	// Block forever
	select {}
}
