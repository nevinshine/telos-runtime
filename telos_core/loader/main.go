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
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

// InodePolicy matches the BPF struct inode_policy_t
type InodePolicy struct {
	Sensitivity uint32
	Reserved    uint32
}

// NetworkPolicy matches the BPF struct network_policy_t
type NetworkPolicy struct {
	Allowed uint32
}

// ExecPolicy matches the BPF struct exec_policy_t (Phase 5)
type ExecPolicy struct {
	Mode        uint32
	Pad         uint32 // Padding for 8-byte alignment expected by cilium/ebpf
	ExpiresNs   uint64
	AllowedBins [8][16]byte
}

// HoneyPayload matches the BPF struct honey_payload_t (Phase 4)
type HoneyPayload struct {
	Length uint32
	Data   [256]byte
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

// BPFEvent represents an event from the kernel ringbuffer
// Must exactly match memory layout of event_t in bpf_lsm.c
type BPFEvent struct {
	PID        uint32   `json:"pid"`
	TaintLevel uint32   `json:"taint_level"`
	Blocked    uint32   `json:"blocked"`
	Comm       [16]byte `json:"-"`
	Action     [16]byte `json:"-"`

	// User-friendly parsed fields
	CommStr string `json:"comm"`
	DescStr string `json:"desc"`
}

// === BPF OBJECTS ===

// Maps loaded from the BPF object
type BPFMaps struct {
	ProcessMap      *ebpf.Map
	ConfigMap       *ebpf.Map
	InodeMap        *ebpf.Map
	NetworkMap      *ebpf.Map
	ExecPolicyMap   *ebpf.Map // [Phase 5]
	MirageMap       *ebpf.Map // [Phase 4]
	HoneyDataMap    *ebpf.Map // [Phase 4]
	TaintedMmapMap  *ebpf.Map // [Phase 2] IPC taint tracking
	TaintedShmidMap *ebpf.Map // [Phase 2] IPC taint tracking
	Events          *ebpf.Map
}

// Links to LSM hooks and kprobes
type BPFLinks struct {
	CheckExec          link.Link
	CheckFile          link.Link
	CheckConnect       link.Link
	TaskAlloc          link.Link
	CheckMmap          link.Link // [Phase 2]
	CheckPtrace        link.Link // [Phase 2]
	CheckShmat         link.Link // [Phase 2]
	MirageReadEnter    link.Link
	MirageReadExit     link.Link
	MirageGetattrEnter link.Link
	MirageGetattrExit  link.Link
}

// === MAIN DAEMON ===

type TelosDaemon struct {
	socketPath       string
	eventsSocketPath string
	bpfObjPath       string
	maps             *BPFMaps
	links            *BPFLinks

	// [Phase 11: Heartbeat Mechanism]
	lastPingTime   time.Time
	pingMutex      sync.Mutex
	failPolicy     string // "OPEN" or "CLOSED"
	watchdogActive bool   // True if Cortex has connected at least once

	// [Phase 3: NDJSON Alert Logger]
	alertFile *os.File
	alertMu   sync.Mutex

	listener       net.Listener
	eventsListener net.Listener
	eventClients   map[net.Conn]struct{}
	clientsMu      sync.Mutex
	done           chan struct{}
}

// === PHASE 12: PROMETHEUS METRICS ===
var (
	metricExecBlocks = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "telos_exec_blocks_total",
			Help: "Total number of unauthorized execve attempts blocked by Telos",
		},
	)
	metricNetworkBlocks = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "telos_network_blocks_total",
			Help: "Total number of unauthorized network connections blocked by Telos",
		},
	)
	metricIfcElevations = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "telos_ifc_elevations_total",
			Help: "Total number of taint elevations triggered by sensitive file access",
		},
	)
	metricActiveDrawbridges = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "telos_active_drawbridges",
			Help: "Current number of actively allowed IP domains in the network_map",
		},
	)

	// [Phase 3] Enhanced Telemetry Metrics
	metricProcessMapSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "telos_process_map_size",
			Help: "Current number of tracked processes in the BPF LRU map",
		},
	)
	metricMirageFeeds = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "telos_mirage_feeds_total",
			Help: "Total number of Mirage deception payloads served to tainted agents",
		},
	)
	metricXdpDrops = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "telos_xdp_drops_total",
			Help: "Total number of XDP packet drops (placeholder for XDP event aggregation)",
		},
	)

	// [Phase 4] Fleet Governance Metrics
	metricMapUtilization = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "telos_bpf_map_utilization",
			Help: "Current number of entries in each tracked BPF map",
		},
		[]string{"map"},
	)
)

func init() {
	prometheus.MustRegister(metricExecBlocks)
	prometheus.MustRegister(metricNetworkBlocks)
	prometheus.MustRegister(metricIfcElevations)
	prometheus.MustRegister(metricActiveDrawbridges)
	prometheus.MustRegister(metricProcessMapSize)
	prometheus.MustRegister(metricMirageFeeds)
	prometheus.MustRegister(metricXdpDrops)
	prometheus.MustRegister(metricMapUtilization)
}

func NewTelosDaemon(socketPath, bpfObjPath string) *TelosDaemon {
	failPolicy := os.Getenv("TELOS_FAIL_POLICY")
	if failPolicy == "" {
		failPolicy = "CLOSED" // Default to maximum security zero-trust
	}

	return &TelosDaemon{
		socketPath:       socketPath,
		eventsSocketPath: "/var/run/telos_events.sock",
		bpfObjPath:       bpfObjPath,
		eventClients:     make(map[net.Conn]struct{}),
		done:             make(chan struct{}),
		failPolicy:       failPolicy,
		watchdogActive:   false, // Initially inactive
		lastPingTime:     time.Now(),
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

	// Start Telemetry Events socket server and Ringbuffer reader
	if err := d.startEventsServer(); err != nil {
		return fmt.Errorf("failed to start events server: %w", err)
	}
	log.Printf("✓ Events stream running on %s", d.eventsSocketPath)

	go d.readEvents()
	go d.orphanCleanupRoutine()

	// [Phase 3] Initialize NDJSON alert logger
	if err := d.initAlertLogger(); err != nil {
		log.Printf("Warning: NDJSON alert logger disabled: %v", err)
	} else {
		log.Println("✓ NDJSON alert logger active → /var/log/telos/alerts.json")
	}

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
		ProcessMap:      coll.Maps["process_map"],
		ConfigMap:       coll.Maps["config_map"],
		InodeMap:        coll.Maps["inode_map"],
		NetworkMap:      coll.Maps["network_map"],
		ExecPolicyMap:   coll.Maps["exec_policy_map"],   // [Phase 5]
		MirageMap:       coll.Maps["mirage_map"],         // [Phase 4]
		HoneyDataMap:    coll.Maps["honey_data_map"],     // [Phase 4]
		TaintedMmapMap:  coll.Maps["tainted_mmap_map"],   // [Phase 2]
		TaintedShmidMap: coll.Maps["tainted_shmid_map"],  // [Phase 2]
		Events:          coll.Maps["events"],
	}

	// Pin maps for external access
	processMapPath := filepath.Join(bpfPinPath, "process_map")
	if err := d.maps.ProcessMap.Pin(processMapPath); err != nil {
		log.Printf("Warning: Failed to pin process_map: %v", err)
	}

	inodeMapPath := filepath.Join(bpfPinPath, "inode_map")
	if err := d.maps.InodeMap.Pin(inodeMapPath); err != nil {
		log.Printf("Warning: Failed to pin inode_map: %v", err)
	}

	networkMapPath := filepath.Join(bpfPinPath, "network_map")
	if err := d.maps.NetworkMap.Pin(networkMapPath); err != nil {
		log.Printf("Warning: Failed to pin network_map: %v", err)
	}

	// [Phase 5] Pin exec_policy_map
	if d.maps.ExecPolicyMap != nil {
		execMapPath := filepath.Join(bpfPinPath, "exec_policy_map")
		if err := d.maps.ExecPolicyMap.Pin(execMapPath); err != nil {
			log.Printf("Warning: Failed to pin exec_policy_map: %v", err)
		}
	}

	// [Phase 4] Pin mirage maps
	if d.maps.MirageMap != nil {
		if err := d.maps.MirageMap.Pin(filepath.Join(bpfPinPath, "mirage_map")); err != nil {
			log.Printf("Warning: Failed to pin mirage_map: %v", err)
		}
	}
	if d.maps.HoneyDataMap != nil {
		if err := d.maps.HoneyDataMap.Pin(filepath.Join(bpfPinPath, "honey_data_map")); err != nil {
			log.Printf("Warning: Failed to pin honey_data_map: %v", err)
		}
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

	// Attach socket_connect
	prog = coll.Programs["telos_check_connect"]
	if prog != nil {
		l, err := link.AttachLSM(link.LSMOptions{
			Program: prog,
		})
		if err != nil {
			log.Printf("Warning: Failed to attach check_connect: %v", err)
		} else {
			d.links.CheckConnect = l
			log.Println("  → Attached lsm/socket_connect")
		}
	}

	// [Phase 2] Attach mmap_file (IPC taint propagation)
	prog = coll.Programs["telos_check_mmap"]
	if prog != nil {
		l, err := link.AttachLSM(link.LSMOptions{
			Program: prog,
		})
		if err != nil {
			log.Printf("Warning: Failed to attach check_mmap: %v", err)
		} else {
			d.links.CheckMmap = l
			log.Println("  → Attached lsm/mmap_file")
		}
	}

	// [Phase 2] Attach ptrace_access_check (IFC boundary enforcement)
	prog = coll.Programs["telos_check_ptrace"]
	if prog != nil {
		l, err := link.AttachLSM(link.LSMOptions{
			Program: prog,
		})
		if err != nil {
			log.Printf("Warning: Failed to attach check_ptrace: %v", err)
		} else {
			d.links.CheckPtrace = l
			log.Println("  → Attached lsm/ptrace_access_check")
		}
	}

	// [Phase 2] Attach shm_shmat (SysV shared memory taint tracking)
	prog = coll.Programs["telos_check_shmat"]
	if prog != nil {
		l, err := link.AttachLSM(link.LSMOptions{
			Program: prog,
		})
		if err != nil {
			log.Printf("Warning: Failed to attach check_shmat: %v", err)
		} else {
			d.links.CheckShmat = l
			log.Println("  → Attached lsm/shm_shmat")
		}
	}

	// Attach Mirage Kprobes (Phase 4)
	if prog := coll.Programs["mirage_read_enter"]; prog != nil {
		kp, err := link.Kprobe("ksys_read", prog, nil)
		if err != nil {
			log.Printf("Warning: attach kprobe/ksys_read: %v", err)
		} else {
			d.links.MirageReadEnter = kp
			log.Println("  → Attached kprobe/ksys_read")
		}
	}
	if prog := coll.Programs["mirage_read_exit"]; prog != nil {
		kp, err := link.Kretprobe("ksys_read", prog, nil)
		if err != nil {
			log.Printf("Warning: attach kretprobe/ksys_read: %v", err)
		} else {
			d.links.MirageReadExit = kp
		}
	}
	if prog := coll.Programs["mirage_getattr_enter"]; prog != nil {
		kp, err := link.Kprobe("vfs_getattr", prog, nil)
		if err != nil {
			log.Printf("Warning: attach kprobe/vfs_getattr: %v", err)
		} else {
			d.links.MirageGetattrEnter = kp
			log.Println("  → Attached kprobe/vfs_getattr")
		}
	}
	if prog := coll.Programs["mirage_getattr_exit"]; prog != nil {
		kp, err := link.Kretprobe("vfs_getattr", prog, nil)
		if err != nil {
			log.Printf("Warning: attach kretprobe/vfs_getattr: %v", err)
		} else {
			d.links.MirageGetattrExit = kp
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
	os.Chmod(d.socketPath, 0666)

	// [Phase 11: Heartbeat Watchdog]
	go d.watchdogRoutine()

	// [Phase 12: Enterprise Observability]
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Println("✓ Prometheus metrics available on :9094/metrics")
		if err := http.ListenAndServe(":9094", nil); err != nil {
			log.Printf("Prometheus server stopped: %v", err)
		}
	}()

	// Accept connections in goroutine
	go d.acceptConnections()

	return nil
}

// startEventsServer starts a separate Unix socket for streaming BPF events to the Telemetry Dashboard
func (d *TelosDaemon) startEventsServer() error {
	os.Remove(d.eventsSocketPath)

	l, err := net.Listen("unix", d.eventsSocketPath)
	if err != nil {
		return err
	}
	d.eventsListener = l
	os.Chmod(d.eventsSocketPath, 0666)

	go func() {
		for {
			conn, err := d.eventsListener.Accept()
			if err != nil {
				select {
				case <-d.done:
					return
				default:
					continue
				}
			}
			d.clientsMu.Lock()
			d.eventClients[conn] = struct{}{}
			d.clientsMu.Unlock()
			log.Printf("[Events] Client connected")
		}
	}()

	return nil
}

// broadcastEvent sends an event to all connected dashboard clients
func (d *TelosDaemon) broadcastEvent(event BPFEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	data = append(data, '\n')

	d.clientsMu.Lock()
	defer d.clientsMu.Unlock()

	for conn := range d.eventClients {
		_, err := conn.Write(data)
		if err != nil {
			conn.Close()
			delete(d.eventClients, conn)
			log.Printf("[Events] Client disconnected")
		}
	}
}

// readEvents continuously reads the BPF ringbuffer and broadcasts to dashboard
func (d *TelosDaemon) readEvents() {
	reader, err := ringbuf.NewReader(d.maps.Events)
	if err != nil {
		log.Printf("[Error] Failed to open ringbuf: %v", err)
		return
	}
	defer reader.Close()

	for {
		select {
		case <-d.done:
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			continue
		}

		var rawEvent struct {
			PID        uint32
			TaintLevel uint32
			Blocked    uint32
			Comm       [16]byte
			Action     [16]byte
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &rawEvent); err != nil {
			log.Printf("[Error] Failed to read BPFEvent from ringbuf: %v (raw size: %d, expected: 44)", err, len(record.RawSample))
			continue
		}

		event := BPFEvent{
			PID:        rawEvent.PID,
			TaintLevel: rawEvent.TaintLevel,
			Blocked:    rawEvent.Blocked,
			Comm:       rawEvent.Comm,
			Action:     rawEvent.Action,
		}

		// Parse C strings (null terminated)
		idxComm := bytes.IndexByte(event.Comm[:], 0)
		if idxComm == -1 {
			idxComm = len(event.Comm)
		}
		event.CommStr = string(event.Comm[:idxComm])

		idxAction := bytes.IndexByte(event.Action[:], 0)
		if idxAction == -1 {
			idxAction = len(event.Action)
		}
		event.DescStr = string(event.Action[:idxAction])

		// [Phase 12: Action Counting]
		if event.Blocked == 1 {
			if event.DescStr == "exec_denied" || event.DescStr == "exec_tainted" {
				metricExecBlocks.Inc()
			} else if event.DescStr == "exfil_blocked" || event.DescStr == "connect_denied" || event.DescStr == "connect_ipv6_denied" {
				metricNetworkBlocks.Inc()
			} else if event.DescStr == "ptrace_denied" {
				metricNetworkBlocks.Inc() // ptrace blocks are security enforcement
			}
		}
		if event.DescStr == "taint_elevate" || event.DescStr == "mmap_taint_inh" || event.DescStr == "shmat_taint_inh" {
			metricIfcElevations.Inc()
		}
		if event.DescStr == "mirage_fed" {
			metricMirageFeeds.Inc()
		}

		// [Phase 3] Write to NDJSON alert log
		d.writeAlertNDJSON(event)

		d.broadcastEvent(event)
	}
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

	case "IPC_PING": // [Phase 11: Heartbeat]
		return d.cmdIPCPing()

	case "UPDATE_TAINT":
		return d.cmdUpdateTaint(cmd.Data)

	case "CLEAR_TAINT":
		return d.cmdClearTaint(cmd.Data)

	case "REGISTER_AGENT":
		return d.cmdRegisterAgent(cmd.Data)

	case "GET_STATE":
		return d.cmdGetState()

	case "UPDATE_INODE":
		return d.cmdUpdateInode(cmd.Data)

	case "UPDATE_NETWORK":
		return d.cmdUpdateNetwork(cmd.Data)

	case "DELETE_NETWORK":
		return d.cmdDeleteNetwork(cmd.Data)

	case "UPDATE_EXEC":
		return d.cmdUpdateExec(cmd.Data)

	case "CLEAR_EXEC":
		return d.cmdClearExec(cmd.Data)

	case "ADD_MIRAGE":
		return d.cmdAddMirage(cmd.Data)

	case "BULK_BLOCK_IPS": // [Phase 4: Threat Intel Feed]
		return d.cmdBulkBlockIPs(cmd.Data)

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

	// Preserve any existing taint state for this PID. The kernel may have
	// elevated taint (e.g., IFC -> CRITICAL) and re-registration must not
	// "reset" that state.
	info := ProcessInfo{PID: pid, TaintLevel: TaintClean}
	var existing ProcessInfo
	if err := d.maps.ProcessMap.Lookup(pid, &existing); err == nil {
		info.TaintLevel = existing.TaintLevel
		info.IsSandboxed = existing.IsSandboxed
		info.Comm = existing.Comm
	}

	// Copy comm name
	if comm != "" {
		copy(info.Comm[:], []byte(comm))
	}

	if err := d.maps.ProcessMap.Put(pid, info); err != nil {
		return IPCResponse{Success: false, Error: err.Error()}
	}

	log.Printf("[REGISTER] Agent PID %d (%s) taint=%d", pid, comm, info.TaintLevel)
	return IPCResponse{Success: true}
}

// cmdUpdateInode updates sensitivity level for an inode
func (d *TelosDaemon) cmdUpdateInode(data map[string]interface{}) IPCResponse {
	inodeFloat, ok := data["inode"].(float64)
	if !ok {
		return IPCResponse{Success: false, Error: "Missing or invalid 'inode'"}
	}
	inode := uint64(inodeFloat)

	sensitivityFloat, ok := data["sensitivity"].(float64)
	if !ok {
		return IPCResponse{Success: false, Error: "Missing or invalid 'sensitivity'"}
	}
	// 0=Clean, 1=Sensitive, 2=Critical
	sensitivity := uint32(sensitivityFloat)

	policy := InodePolicy{
		Sensitivity: sensitivity,
	}

	if err := d.maps.InodeMap.Put(inode, policy); err != nil {
		return IPCResponse{Success: false, Error: err.Error()}
	}

	log.Printf("[INODE] Updated inode %d -> sensitivity %d", inode, sensitivity)
	return IPCResponse{Success: true}
}

// cmdUpdateNetwork updates the allowed IP list
func (d *TelosDaemon) cmdUpdateNetwork(data map[string]interface{}) IPCResponse {
	ipFloat, ok := data["ip"].(float64)
	if !ok {
		return IPCResponse{Success: false, Error: "Missing or invalid 'ip'"}
	}
	ip := uint32(ipFloat)

	allowedFloat, ok := data["allowed"].(float64)
	if !ok {
		return IPCResponse{Success: false, Error: "Missing or invalid 'allowed'"}
	}
	allowed := uint32(allowedFloat)

	policy := NetworkPolicy{
		Allowed: allowed,
	}

	if err := d.maps.NetworkMap.Put(ip, policy); err != nil {
		return IPCResponse{Success: false, Error: err.Error()}
	}

	metricActiveDrawbridges.Inc()

	log.Printf("[NETWORK] Updated IP %d -> allowed %d", ip, allowed)
	return IPCResponse{Success: true}
}

// cmdDeleteNetwork removes an IP from the allowlist map entirely
func (d *TelosDaemon) cmdDeleteNetwork(data map[string]interface{}) IPCResponse {
	ipFloat, ok := data["ip"].(float64)
	if !ok {
		return IPCResponse{Success: false, Error: "Missing or invalid 'ip'"}
	}
	ip := uint32(ipFloat)

	// Delete the key from the map
	if err := d.maps.NetworkMap.Delete(ip); err != nil {
		// It's not an error if the key doesn't exist (already deleted)
		log.Printf("[NETWORK] Warning: Failed to delete IP %d: %v", ip, err)
	} else {
		metricActiveDrawbridges.Dec()
		log.Printf("[NETWORK] Deleted IP %d (Rule Expired)", ip)
	}

	return IPCResponse{Success: true}
}

// cmdUpdateExec sets execution policy for a PID (Phase 5)
func (d *TelosDaemon) cmdUpdateExec(data map[string]interface{}) IPCResponse {
	pidFloat, ok := data["pid"].(float64)
	if !ok {
		return IPCResponse{Success: false, Error: "Missing or invalid 'pid'"}
	}
	pid := uint32(pidFloat)

	modeFloat, ok := data["mode"].(float64)
	if !ok {
		modeFloat = 1 // Default: enforce
	}

	// Parse allowed_bins array
	policy := ExecPolicy{
		Mode: uint32(modeFloat),
	}

	if bins, ok := data["allowed_bins"].([]interface{}); ok {
		for i, bin := range bins {
			if i >= 8 {
				break
			}
			if name, ok := bin.(string); ok {
				copy(policy.AllowedBins[i][:], name)
			}
		}
	}

	if d.maps.ExecPolicyMap == nil {
		return IPCResponse{Success: false, Error: "exec_policy_map not loaded"}
	}

	if err := d.maps.ExecPolicyMap.Put(pid, policy); err != nil {
		return IPCResponse{Success: false, Error: err.Error()}
	}

	log.Printf("[EXEC] PID %d -> mode=%d bins=%v", pid, policy.Mode, data["allowed_bins"])
	return IPCResponse{Success: true}
}

// cmdClearExec removes execution policy for a PID (Phase 5)
func (d *TelosDaemon) cmdClearExec(data map[string]interface{}) IPCResponse {
	pidFloat, ok := data["pid"].(float64)
	if !ok {
		return IPCResponse{Success: false, Error: "Missing or invalid 'pid'"}
	}
	pid := uint32(pidFloat)

	if d.maps.ExecPolicyMap == nil {
		return IPCResponse{Success: false, Error: "exec_policy_map not loaded"}
	}

	if err := d.maps.ExecPolicyMap.Delete(pid); err != nil {
		log.Printf("[EXEC] Warning: Failed to clear PID %d: %v", pid, err)
	} else {
		log.Printf("[EXEC] Cleared policy for PID %d", pid)
	}

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

// cmdAddMirage setups a deceptive honey token for an inode
func (d *TelosDaemon) cmdAddMirage(data map[string]interface{}) IPCResponse {
	inodeFloat, ok := data["inode"].(float64)
	if !ok {
		return IPCResponse{Success: false, Error: "Missing or invalid 'inode'"}
	}
	inode := uint64(inodeFloat)

	honeyIdFloat, ok := data["honey_id"].(float64)
	if !ok {
		return IPCResponse{Success: false, Error: "Missing or invalid 'honey_id'"}
	}
	honeyId := uint32(honeyIdFloat)

	payloadStr, ok := data["payload"].(string)
	if !ok {
		return IPCResponse{Success: false, Error: "Missing or invalid 'payload'"}
	}

	if len(payloadStr) > 256 {
		return IPCResponse{Success: false, Error: "Payload too large (max 256 bytes)"}
	}

	payload := HoneyPayload{
		Length: uint32(len(payloadStr)),
	}
	copy(payload.Data[:], payloadStr)

	// Update the honey content map first
	if err := d.maps.HoneyDataMap.Put(honeyId, payload); err != nil {
		return IPCResponse{Success: false, Error: "Failed to update honey_data_map: " + err.Error()}
	}

	// Then link the inode to the honey id
	if err := d.maps.MirageMap.Put(inode, honeyId); err != nil {
		return IPCResponse{Success: false, Error: "Failed to update mirage_map: " + err.Error()}
	}

	log.Printf("[MIRAGE] Registered Honey Token %d for Inode %d (%d bytes)", honeyId, inode, payload.Length)
	return IPCResponse{Success: true}
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

	// [Phase 3] Close NDJSON alert log
	if d.alertFile != nil {
		d.alertFile.Close()
	}

	// Detach LSM hooks and kprobes
	if d.links != nil {
		if d.links.CheckExec != nil {
			d.links.CheckExec.Close()
		}
		if d.links.CheckFile != nil {
			d.links.CheckFile.Close()
		}
		if d.links.CheckConnect != nil {
			d.links.CheckConnect.Close()
		}
		if d.links.TaskAlloc != nil {
			d.links.TaskAlloc.Close()
		}
		// [Phase 2] Close IPC tracking hooks
		if d.links.CheckMmap != nil {
			d.links.CheckMmap.Close()
		}
		if d.links.CheckPtrace != nil {
			d.links.CheckPtrace.Close()
		}
		if d.links.CheckShmat != nil {
			d.links.CheckShmat.Close()
		}
		if d.links.MirageReadEnter != nil {
			d.links.MirageReadEnter.Close()
		}
		if d.links.MirageReadExit != nil {
			d.links.MirageReadExit.Close()
		}
		if d.links.MirageGetattrEnter != nil {
			d.links.MirageGetattrEnter.Close()
		}
		if d.links.MirageGetattrExit != nil {
			d.links.MirageGetattrExit.Close()
		}
	}

	// Clean up socket
	os.Remove(d.socketPath)

	log.Println("TELOS CORE offline")
}

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

// === PHASE 11: HEARTBEAT WATCHDOG & EMERGENCY PROTOCOLS ===

// cmdIPCPing updates the last seen timestamp from Cortex
func (d *TelosDaemon) cmdIPCPing() IPCResponse {
	d.pingMutex.Lock()
	defer d.pingMutex.Unlock()
	d.lastPingTime = time.Now()

	if !d.watchdogActive {
		log.Println("✓ Core Watchdog Active: Receiving IPC_PINGS from Cortex.")
		d.watchdogActive = true

		// If we were previously Failed-Open, reset to Enforcing mode
		key := uint32(0)
		var cfg Config
		if err := d.maps.ConfigMap.Lookup(&key, &cfg); err == nil && cfg.Enabled == 0 {
			cfg.Enabled = 1
			d.maps.ConfigMap.Update(&key, &cfg, ebpf.UpdateAny)
			log.Println("[RECOVERY] Cortex reconnect detected. Enforcement restored (Enabled = 1).")
		}
	}
	return IPCResponse{Success: true}
}

// watchdogRoutine monitors the pulse of the Control Plane
func (d *TelosDaemon) watchdogRoutine() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.done:
			return
		case <-ticker.C:
			d.pingMutex.Lock()
			active := d.watchdogActive
			last := d.lastPingTime
			d.pingMutex.Unlock()

			if !active {
				continue // Don't trigger if Cortex hasn't attached yet
			}

			if time.Since(last) > 5*time.Second {
				log.Println("[EMERGENCY] Cortex Control Plane missed heartbeat timeout (> 5s).")
				d.pingMutex.Lock()
				d.watchdogActive = false // Prevent retriggers until connection restores
				d.pingMutex.Unlock()

				if d.failPolicy == "OPEN" {
					d.executeFailOpen()
				} else {
					d.executeFailClosed()
				}
			}
		}
	}
}

// executeFailOpen prioritizes Availability by disabling eBPF blocking hooks
func (d *TelosDaemon) executeFailOpen() {
	log.Println("[FAIL-OPEN] Transitioning eBPF gates to Audit-Only mode to preserve traffic.")
	key := uint32(0)
	var cfg Config
	if err := d.maps.ConfigMap.Lookup(&key, &cfg); err != nil {
		log.Printf("[Error] Fail-Open could not read config_map: %v", err)
		return
	}

	cfg.Enabled = 0 // Disable -EPERM enforcement drops
	if err := d.maps.ConfigMap.Update(&key, &cfg, ebpf.UpdateAny); err != nil {
		log.Printf("[Error] Fail-Open could not write to config_map: %v", err)
		return
	}
	log.Println("[FAIL-OPEN] Complete. Telos is now Audit-Only.")
}

// executeFailClosed prioritizes Confidentiality by severing all active dynamic network connections universally
func (d *TelosDaemon) executeFailClosed() {
	log.Println("[FAIL-CLOSED] Iterating and flushing dynamic Drawbridge allocations (network_map)...")

	iterator := d.maps.NetworkMap.Iterate()
	var ipKey uint32
	var policy NetworkPolicy

	flushCount := 0
	for iterator.Next(&ipKey, &policy) {
		if err := d.maps.NetworkMap.Delete(&ipKey); err == nil {
			flushCount++
			metricActiveDrawbridges.Dec()
		}
	}
	if err := iterator.Err(); err != nil {
		log.Printf("[Error] Iterator failed during Fail-Closed network_map flush: %v", err)
	}

	log.Printf("[FAIL-CLOSED] Complete. Slammed %d open specific domains shut.", flushCount)
	log.Println("[FAIL-CLOSED] Enforcement remains active (Zero-Trust). Traffic is blackholed.")
}

// === PHASE 1: ORPHAN CLEANUP + PHASE 4: MAP UTILIZATION SAMPLING ===

// orphanCleanupRoutine periodically purges dead processes from the BPF LRU map
// to prevent map contention and eviction vulnerabilities.
// Also samples BPF map sizes for Prometheus fleet governance metrics.
func (d *TelosDaemon) orphanCleanupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.done:
			return
		case <-ticker.C:
			// Iterate over all PIDs in the map
			var pid uint32
			var info ProcessInfo
			var evicted uint32
			var alive uint32

			iterator := d.maps.ProcessMap.Iterate()
			for iterator.Next(&pid, &info) {
				// Check if process still exists in /proc
				procPath := fmt.Sprintf("/proc/%d", pid)
				_, err := os.Stat(procPath)
				if os.IsNotExist(err) {
					// Process is dead, delete from map
					if err := d.maps.ProcessMap.Delete(&pid); err == nil {
						evicted++
					}
				} else {
					alive++
				}
			}

			if evicted > 0 {
				log.Printf("✓ Orphan Cleanup: Purged %d dead PID states from BPF LRU map", evicted)
			}

			// [Phase 3+4] Update Prometheus gauges
			metricProcessMapSize.Set(float64(alive))
			metricMapUtilization.WithLabelValues("process_map").Set(float64(alive))

			// Sample network_map size
			var netCount float64
			var ipKey uint32
			var netPolicy NetworkPolicy
			netIter := d.maps.NetworkMap.Iterate()
			for netIter.Next(&ipKey, &netPolicy) {
				netCount++
			}
			metricMapUtilization.WithLabelValues("network_map").Set(netCount)

			// Sample inode_map size
			var inodeCount float64
			var inoKey uint64
			var inoPolicy InodePolicy
			inoIter := d.maps.InodeMap.Iterate()
			for inoIter.Next(&inoKey, &inoPolicy) {
				inodeCount++
			}
			metricMapUtilization.WithLabelValues("inode_map").Set(inodeCount)
		}
	}
}

// === PHASE 3: NDJSON ALERT LOGGER ===

const (
	alertLogDir     = "/var/log/telos"
	alertLogFile    = "/var/log/telos/alerts.json"
	alertMaxSizeBytes = 50 * 1024 * 1024 // 50 MB
)

// NDJSONAlert is the structured alert format for SIEM ingestion
type NDJSONAlert struct {
	Timestamp  string `json:"timestamp"`
	Hostname   string `json:"hostname"`
	PID        uint32 `json:"pid"`
	Comm       string `json:"comm"`
	Action     string `json:"action"`
	TaintLevel uint32 `json:"taint_level"`
	Blocked    bool   `json:"blocked"`
	Engine     string `json:"engine"`
}

// initAlertLogger creates the NDJSON log file and directory
func (d *TelosDaemon) initAlertLogger() error {
	if err := os.MkdirAll(alertLogDir, 0755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}

	f, err := os.OpenFile(alertLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open alert log: %w", err)
	}
	d.alertFile = f
	return nil
}

// writeAlertNDJSON writes a single event as a JSON line to the alert log
func (d *TelosDaemon) writeAlertNDJSON(event BPFEvent) {
	if d.alertFile == nil {
		return
	}

	hostname, _ := os.Hostname()
	alert := NDJSONAlert{
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		Hostname:   hostname,
		PID:        event.PID,
		Comm:       event.CommStr,
		Action:     event.DescStr,
		TaintLevel: event.TaintLevel,
		Blocked:    event.Blocked == 1,
		Engine:     "telos_core",
	}

	data, err := json.Marshal(alert)
	if err != nil {
		return
	}
	data = append(data, '\n')

	d.alertMu.Lock()
	defer d.alertMu.Unlock()

	// Check file size for rotation
	if stat, err := d.alertFile.Stat(); err == nil {
		if stat.Size() > alertMaxSizeBytes {
			d.alertFile.Close()
			os.Rename(alertLogFile, alertLogFile+".1")
			f, err := os.OpenFile(alertLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Printf("[AlertLog] Failed to rotate: %v", err)
				d.alertFile = nil
				return
			}
			d.alertFile = f
			log.Println("✓ Alert log rotated → alerts.json.1")
		}
	}

	d.alertFile.Write(data)
}

// === PHASE 4: BULK THREAT INTEL FEED ===

// cmdBulkBlockIPs accepts a JSON array of IPv4 addresses and batch-inserts
// them into the network_map as blocked (allowed=0) entries.
// This enables Cortex to push threat intel feed updates atomically.
func (d *TelosDaemon) cmdBulkBlockIPs(data map[string]interface{}) IPCResponse {
	ipsRaw, ok := data["ips"]
	if !ok {
		return IPCResponse{Success: false, Error: "missing 'ips' field"}
	}

	ipsList, ok := ipsRaw.([]interface{})
	if !ok {
		return IPCResponse{Success: false, Error: "'ips' must be an array"}
	}

	blocked := 0
	for _, ipRaw := range ipsList {
		ipStr, ok := ipRaw.(string)
		if !ok {
			continue
		}

		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		ip4 := ip.To4()
		if ip4 == nil {
			continue // Skip non-IPv4
		}

		// Convert to network byte order (uint32)
		ipKey := binary.BigEndian.Uint32(ip4)
		policy := NetworkPolicy{Allowed: 0} // Block

		if err := d.maps.NetworkMap.Update(&ipKey, &policy, ebpf.UpdateAny); err != nil {
			log.Printf("[ThreatIntel] Failed to block %s: %v", ipStr, err)
			continue
		}
		blocked++
	}

	log.Printf("✓ Threat Intel: Bulk-blocked %d IPs from feed", blocked)
	return IPCResponse{
		Success: true,
		Data:    fmt.Sprintf("blocked %d IPs", blocked),
	}
}
