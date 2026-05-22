package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Events
const (
	EventsSocket = "/var/run/telos_events.sock"
	CortexLog    = "/tmp/telos_cortex.log"
)

// --- Styling (The Midnight & Neon Astro Theme) ---
var (
	colorBlack     = lipgloss.Color("#000000")
	colorSlate     = lipgloss.Color("#1E293B")
	colorSlateDim  = lipgloss.Color("#0F172A")
	colorCyan      = lipgloss.Color("#06B6D4")
	colorViolet    = lipgloss.Color("#8B5CF6")
	colorEmerald   = lipgloss.Color("#10B981")
	colorAmber     = lipgloss.Color("#F59E0B")
	colorRose      = lipgloss.Color("#F43F5E")
	colorWhiteDim  = lipgloss.Color("#9CA3AF")
	colorWhiteHigh = lipgloss.Color("#F8FAFC")

	styleBase = lipgloss.NewStyle().
			Foreground(colorWhiteHigh).
			Background(colorBlack)

	styleHeader = lipgloss.NewStyle().
			Foreground(colorCyan).
			Bold(true)

	styleRowClean = lipgloss.NewStyle().
			Foreground(colorWhiteDim)

	styleRowTainted = lipgloss.NewStyle().
			Foreground(colorAmber)

	styleBadgeAllow = lipgloss.NewStyle().
			Foreground(colorBlack).
			Background(colorEmerald).
			Padding(0, 1).
			Bold(true)

	styleBadgeBlock = lipgloss.NewStyle().
			Foreground(colorBlack).
			Background(colorRose).
			Padding(0, 1).
			Bold(true)

	styleBadgeMonitor = lipgloss.NewStyle().
				Foreground(colorBlack).
				Background(colorAmber).
				Padding(0, 1).
				Bold(true)
)

// --- Types ---
type bpfEvent struct {
	Timestamp  string `json:"timestamp"`
	PID        int    `json:"pid"`
	TaintLevel int    `json:"taint_level"`
	Action     string `json:"desc"`
}

type model struct {
	width          int
	height         int
	events         []string
	cpu            float64
	mem            int
	xdpDrops       int
	lsmHooks       int
	bpfEventChan   chan string
	cortexLogChan  chan string
}

// Custom msg types for tea.Cmd
type bpfMsg string
type cortexMsg string
type tickMsg time.Time

func main() {
	m := model{
		events:        make([]string, 0, 100),
		cpu:           0.2,
		mem:           14,
		xdpDrops:      12,
		lsmHooks:      44,
		bpfEventChan:  make(chan string, 100),
		cortexLogChan: make(chan string, 100),
	}

	// Start background workers
	go tailCortexLog(m.cortexLogChan)
	go streamBPFEvents(m.bpfEventChan)

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
}

// --- Background Workers ---
func tailCortexLog(out chan string) {
	// Simple tail implementation
	file, err := os.Open(CortexLog)
	if err != nil {
		out <- fmt.Sprintf("Error opening cortex log: %v", err)
		return
	}
	defer file.Close()

	file.Seek(0, 2) // Seek to end
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
				out <- lipgloss.NewStyle().Foreground(colorCyan).Render(fmt.Sprintf("[ALLOW]  intent_decl      cortex (%s)", strings.TrimSpace(parts[1])))
			}
		} else if strings.Contains(line, "✅ Intent APPROVED") {
			out <- lipgloss.NewStyle().Foreground(colorEmerald).Render("[ALLOW]  network_gate     OPEN")
		} else if strings.Contains(line, "❌ Intent DENIED") {
			out <- lipgloss.NewStyle().Foreground(colorRose).Render("[BLOCK]  intent_denied    " + line)
		}
	}
}

func streamBPFEvents(out chan string) {
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
				action := event.Action
				var styledAction string
				if action == "exec_denied" {
					styledAction = styleBadgeBlock.Render("BLOCK") + "  exec             " + fmt.Sprintf("PID %d", event.PID)
				} else if action == "taint_elevate" {
					styledAction = styleBadgeMonitor.Render("TAINT") + "  lsm_hook         " + fmt.Sprintf("PID %d", event.PID)
				} else {
					styledAction = lipgloss.NewStyle().Foreground(colorWhiteDim).Render(fmt.Sprintf("[INFO]   %-16s PID %d", action, event.PID))
				}
				out <- fmt.Sprintf("%s  %s", time.Now().Format("15:04:05"), styledAction)
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
	)
}

func waitForBPF(sub chan string) tea.Cmd {
	return func() tea.Msg { return bpfMsg(<-sub) }
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
	case bpfMsg:
		m.events = append(m.events, string(msg))
		if len(m.events) > 10 {
			m.events = m.events[1:]
		}
		m.xdpDrops += 1
		m.lsmHooks += 10
		return m, waitForBPF(m.bpfEventChan)
	case cortexMsg:
		m.events = append(m.events, string(msg))
		if len(m.events) > 10 {
			m.events = m.events[1:]
		}
		return m, waitForCortex(m.cortexLogChan)
	case tickMsg:
		// Mock stats update
		return m, tick()
	}
	return m, nil
}

func (m model) View() string {
	if m.width == 0 {
		return "Initializing..."
	}

	header := styleHeader.Render(fmt.Sprintf("▲ TELOS v2.0   ● LIVE   %s", time.Now().Format("15:04:05")))
	separator := lipgloss.NewStyle().Foreground(colorSlate).Render(strings.Repeat("━", m.width))

	vitals := fmt.Sprintf(`  VITALS 
  cpu %.1f%%   mem %dMB   [ ▂▃▄▅▇█ ]  XDP drops/s: %d  LSM hooks: %d`, m.cpu, m.mem, m.xdpDrops, m.lsmHooks)

	table := `  ENFORCEMENT ARENA
  ╭──────────────────────────────────────────────────────────────╮
  │  PID     PROCESS      STATUS       NETWORK        ACTION     │
  │  1042    nginx        ● Clean      ● Allow        ` + styleBadgeAllow.Render("Allow") + `      │
  │  3391    node         ● Clean      ● Allow        ` + styleBadgeAllow.Render("Allow") + `      │
  │                                                              │
  │ ❯ 8991   bash         ` + lipgloss.NewStyle().Foreground(colorAmber).Render("● TAINTED") + `    ` + lipgloss.NewStyle().Foreground(colorRose).Render("● BLOCK") + `        ` + styleBadgeMonitor.Render("Monitor") + `    │
  │   ╰─► sys_read (socket -> buffer)                            │
  │   ╰─► bpf_lsm_file_open (signature match)                    │
  │                                                              │
  ╰──────────────────────────────────────────────────────────────╯`

	var streamBuilder strings.Builder
	streamBuilder.WriteString("  LIVE EVENT STREAM (TRACING)\n  ────────────────────────────────────────────────────────\n")
	for _, e := range m.events {
		streamBuilder.WriteString("  " + e + "\n")
	}

	return styleBase.Render(fmt.Sprintf("%s\n%s\n\n%s\n\n%s\n\n%s", header, separator, vitals, table, streamBuilder.String()))
}
