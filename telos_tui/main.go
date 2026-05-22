package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Events
const (
	EventsSocket = "/var/run/telos_events.sock"
	CortexLog    = "/tmp/telos_cortex.log"
)

// --- COLORS (Cyber-Grid Theme) ---
var (
	cBrand   = lipgloss.Color("#FF00FF") // Neon Magenta
	cCyan    = lipgloss.Color("#00E5FF") // Electric Cyan
	cGreen   = lipgloss.Color("#00FF66") // Matrix Green
	cRed     = lipgloss.Color("#FF0033") // Danger Red
	cDark    = lipgloss.Color("#333333") // Dark Grey borders
	cText    = lipgloss.Color("#FFFFFF") // Pure White text
	cSubtext = lipgloss.Color("#888888") // Dim text
)

// --- STYLES ---
var (
	baseStyle = lipgloss.NewStyle().Padding(1, 2).Foreground(cText).Background(lipgloss.Color("#000000"))

	// Header
	headerStyle = lipgloss.NewStyle().Foreground(cBrand).Bold(true)
	lineStyle   = lipgloss.NewStyle().Foreground(cDark)
	activeStyle = lipgloss.NewStyle().Foreground(cGreen).Bold(true)

	// Cards
	cardBorder = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(cDark).
			Padding(0, 1).
			Width(25)

	cardTitle = lipgloss.NewStyle().Foreground(cCyan).Bold(true)

	// Arena
	arenaTitle = lipgloss.NewStyle().Foreground(cBrand).Bold(true).MarginTop(1)
	arenaLine  = lipgloss.NewStyle().Foreground(cDark)

	// Statuses
	safeText  = lipgloss.NewStyle().Foreground(cGreen)
	alertText = lipgloss.NewStyle().Foreground(cRed)
	dimText   = lipgloss.NewStyle().Foreground(cSubtext)

	// Ticker / Stream
	streamTitle = lipgloss.NewStyle().Foreground(cBrand).Bold(true).MarginTop(1)
)

// --- Types ---
type bpfEvent struct {
	Timestamp  string `json:"timestamp"`
	PID        int    `json:"pid"`
	TaintLevel int    `json:"taint_level"`
	Action     string `json:"desc"`
}

type ProcessStatus struct {
	PID       int
	Name      string
	Integrity string
	State     string
	Action    string
	IsBlocked bool
	IsTainted bool
	LastEvent time.Time
}

type model struct {
	width         int
	height        int
	events        []string
	cpu           float64
	mem           int
	xdpDrops      int
	lsmHooks      int
	bpfEventChan  chan bpfEvent
	cortexLogChan chan string
	spinner       spinner.Model
	processes     map[int]*ProcessStatus
}

// Custom msg types for tea.Cmd
type cortexMsg string
type tickMsg time.Time

func main() {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(cBrand)

	m := model{
		events:        make([]string, 0, 100),
		cpu:           0.0,
		mem:           0,
		xdpDrops:      0,
		lsmHooks:      0,
		bpfEventChan:  make(chan bpfEvent, 100),
		cortexLogChan: make(chan string, 100),
		spinner:       s,
		processes:     make(map[int]*ProcessStatus),
	}

	// Start background workers
	go tailCortexLog(m.cortexLogChan)
	go streamBPFEvents(m.bpfEventChan)

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}

// --- System Info Helpers ---
func getProcessName(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		// Fallback for mocked PIDs
		if pid == 1042 {
			return "nginx"
		} else if pid == 3391 {
			return "node"
		} else if pid == 8991 {
			return "bash"
		}
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

func getMemoryPercent() int {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var total, available int
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fmt.Sscanf(line, "MemTotal: %d", &total)
		} else if strings.HasPrefix(line, "MemAvailable:") {
			fmt.Sscanf(line, "MemAvailable: %d", &available)
		}
	}
	if total == 0 {
		return 0
	}
	return int(float64(total-available) / float64(total) * 100)
}

func getCPUPercent() float64 {
	// A simple mock for CPU, reading /proc/stat correctly requires two samples.
	// For immediate UI feedback without blocking, we'll return a static/simulated value.
	return 12.4
}

// --- Background Workers ---
func tailCortexLog(out chan string) {
	file, err := os.Open(CortexLog)
	if err != nil {
		// Log might not exist immediately
		time.Sleep(1 * time.Second)
	}
	if file != nil {
		defer file.Close()
		file.Seek(0, 2)
	}

	for {
		if file == nil {
			file, err = os.Open(CortexLog)
			if err != nil {
				time.Sleep(2 * time.Second)
				continue
			}
			file.Seek(0, 2)
		}

		reader := bufio.NewReader(file)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			line = strings.TrimSpace(line)
			if strings.Contains(line, "[Intent]") {
				parts := strings.SplitN(line, "[Intent]", 2)
				if len(parts) == 2 {
					out <- safeText.Render(fmt.Sprintf("CORTEX: intent_decl (%s)", strings.TrimSpace(parts[1])))
				}
			} else if strings.Contains(line, "✅ Intent APPROVED") {
				out <- safeText.Render("CORTEX: network_gate OPEN")
			} else if strings.Contains(line, "❌ Intent DENIED") {
				out <- alertText.Render("CORTEX: intent_denied")
			}
		}
	}
}

func streamBPFEvents(out chan bpfEvent) {
	for {
		conn, err := net.Dial("unix", EventsSocket)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			var event bpfEvent
			if err := json.Unmarshal(scanner.Bytes(), &event); err == nil {
				out <- event
			}
		}
		conn.Close()
	}
}

// --- Bubble Tea Interface ---
func (m model) Init() tea.Cmd {
	return tea.Batch(
		waitForBPF(m.bpfEventChan),
		waitForCortex(m.cortexLogChan),
		tick(),
		m.spinner.Tick,
	)
}

func waitForBPF(sub chan bpfEvent) tea.Cmd {
	return func() tea.Msg { return <-sub }
}

func waitForCortex(sub chan string) tea.Cmd {
	return func() tea.Msg { return cortexMsg(<-sub) }
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case bpfEvent:
		// Process Event Logic
		pid := msg.PID
		if _, exists := m.processes[pid]; !exists {
			m.processes[pid] = &ProcessStatus{
				PID:       pid,
				Name:      getProcessName(pid),
				Integrity: "VERIFIED",
				State:     "LISTENING",
				Action:    "ALLOW",
			}
		}
		
		proc := m.processes[pid]
		proc.LastEvent = time.Now()
		m.lsmHooks++

		action := msg.Action
		var styledAction string
		if action == "exec_denied" || action == "exfil_blocked" {
			proc.Action = "BLOCKED"
			proc.State = "EXFILTRATING"
			proc.IsBlocked = true
			proc.IsTainted = true
			proc.Integrity = "TAINTED"
			m.xdpDrops++
			styledAction = alertText.Render(fmt.Sprintf("%s PID:%d", action, pid))
		} else if action == "taint_elevate" {
			proc.Integrity = "TAINTED"
			proc.State = "COMPROMISED"
			proc.IsTainted = true
			styledAction = alertText.Render(fmt.Sprintf("%s PID:%d", action, pid))
		} else {
			styledAction = dimText.Render(fmt.Sprintf("%s PID:%d", action, pid))
		}

		m.events = append(m.events, fmt.Sprintf("%s %s", time.Now().Format("15:04:05"), styledAction))
		if len(m.events) > 20 {
			m.events = m.events[1:]
		}
		return m, waitForBPF(m.bpfEventChan)

	case cortexMsg:
		m.events = append(m.events, fmt.Sprintf("%s %s", time.Now().Format("15:04:05"), string(msg)))
		if len(m.events) > 20 {
			m.events = m.events[1:]
		}
		return m, waitForCortex(m.cortexLogChan)

	case tickMsg:
		m.mem = getMemoryPercent()
		m.cpu = getCPUPercent()
		return m, tick()

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m model) View() string {
	if m.width == 0 {
		return ""
	}

	// 1. HEADER
	header := fmt.Sprintf("%s %s   %s",
		headerStyle.Render("⣿ TELOS RUNTIME"),
		dimText.Render("v2.0"),
		lineStyle.Render(strings.Repeat("─", 45)),
	)
	status := activeStyle.Render(fmt.Sprintf("◉ ACTIVE   %s", time.Now().Format("15:04:05")))
	headerRow := lipgloss.JoinHorizontal(lipgloss.Bottom, header, "  ", status)

	// 2. TOP CARDS (Horizontal Flexbox)
	sysCard := cardBorder.Render(fmt.Sprintf("%s\nCPU  [%s] %.0f%%\nMEM  [%s] %d%%",
		cardTitle.Render("SYSTEM VITALS"),
		safeText.Render("████")+dimText.Render("░░░░░░"), m.cpu,
		alertText.Render("███████")+dimText.Render("░░░"), m.mem,
	))

	netCard := cardBorder.Render(fmt.Sprintf("%s\nBLOCKED %10s\nALLOWED %10s",
		cardTitle.Render("NETWORK (XDP)"),
		alertText.Render(fmt.Sprintf("%d req/s", m.xdpDrops)),
		safeText.Render(fmt.Sprintf("%d req/s", m.lsmHooks*2)), // Mocking allowed based on hooks
	))

	lsmCard := cardBorder.Render(fmt.Sprintf("%s\nINTERCEPTS %7s\nTAINTED %10s",
		cardTitle.Render("KERNEL (LSM)"),
		safeText.Render(fmt.Sprintf("%d ev/s", m.lsmHooks)),
		alertText.Render(fmt.Sprintf("%d ev/s", m.xdpDrops)),
	))

	cardsRow := lipgloss.JoinHorizontal(lipgloss.Top, sysCard, "  ", netCard, "  ", lsmCard)

	// 3. THREAT ARENA (Process Table)
	arenaHead := fmt.Sprintf(" %s %s", arenaTitle.Render("THREAT ARENA"), arenaLine.Render(strings.Repeat("┈", 70)))

	colPID := lipgloss.NewStyle().Width(8)
	colTarget := lipgloss.NewStyle().Width(14)
	colIntegrity := lipgloss.NewStyle().Width(15)
	colState := lipgloss.NewStyle().Width(20)
	colAction := lipgloss.NewStyle().Width(12)

	headerTable := lipgloss.JoinHorizontal(lipgloss.Left,
		colPID.Render("PID"),
		colTarget.Render("TARGET"),
		colIntegrity.Render("INTEGRITY"),
		colState.Render("STATE"),
		colAction.Render("ACTION"))

	// Sort processes by LastEvent descending
	var procs []*ProcessStatus
	for _, p := range m.processes {
		procs = append(procs, p)
	}
	sort.Slice(procs, func(i, j int) bool {
		return procs[i].LastEvent.After(procs[j].LastEvent)
	})

	var tableRows []string
	tableRows = append(tableRows, "  "+headerTable)

	for i, p := range procs {
		if i >= 6 {
			break // Show max 6 rows
		}
		
		pidStr := fmt.Sprintf("%d", p.PID)
		if p.IsTainted || p.IsBlocked {
			pidStr = headerStyle.Render("❯") + " " + pidStr
		}

		integrity := safeText.Render(p.Integrity)
		if p.IsTainted {
			integrity = alertText.Render(p.Integrity)
		}

		state := safeText.Render(p.State)
		if p.IsBlocked || p.IsTainted {
			state = alertText.Render(p.State)
		}

		action := fmt.Sprintf("[ %s ]", p.Action)
		
		row := lipgloss.JoinHorizontal(lipgloss.Left,
			colPID.Render(pidStr),
			colTarget.Render(p.Name),
			colIntegrity.Render(integrity),
			colState.Render(state),
			colAction.Render(action))
		
		tableRows = append(tableRows, "  "+row)
	}

	if len(procs) == 0 {
		tableRows = append(tableRows, "  "+dimText.Render("No active processes being tracked."))
	}

	table := lipgloss.JoinVertical(lipgloss.Left, tableRows...)

	// 4. VERTICAL LIVE STREAM
	streamHead := fmt.Sprintf(" %s %s", streamTitle.Render("EVENT STREAM"), arenaLine.Render(strings.Repeat("┈", 70)))
	
	var streamParts []string
	start := len(m.events) - 8 // Show last 8 events
	if start < 0 {
		start = 0
	}
	for i := start; i < len(m.events); i++ {
		streamParts = append(streamParts, "  "+m.events[i])
	}
	
	if len(streamParts) == 0 {
		streamParts = append(streamParts, "  "+dimText.Render("Waiting for live trace events..."))
	}
	
	streamView := lipgloss.JoinVertical(lipgloss.Left, streamParts...)

	// ASSEMBLE
	ui := lipgloss.JoinVertical(lipgloss.Left,
		headerRow,
		"",
		cardsRow,
		"",
		arenaHead,
		"",
		table,
		"",
		streamHead,
		"",
		streamView,
	)

	return baseStyle.Render(ui) + "\n"
}
