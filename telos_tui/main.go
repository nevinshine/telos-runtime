package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

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

	// Ticker
	tickerPrefix = lipgloss.NewStyle().Foreground(cBrand).Bold(true).MarginTop(1)
)

// --- Types ---
type bpfEvent struct {
	Timestamp  string `json:"timestamp"`
	PID        int    `json:"pid"`
	TaintLevel int    `json:"taint_level"`
	Action     string `json:"desc"`
}

type model struct {
	width         int
	height        int
	events        []string
	cpu           float64
	mem           int
	xdpDrops      int
	lsmHooks      int
	bpfEventChan  chan string
	cortexLogChan chan string
}

// Custom msg types for tea.Cmd
type bpfMsg string
type cortexMsg string
type tickMsg time.Time

func main() {
	m := model{
		events:        make([]string, 0, 100),
		cpu:           42.0,
		mem:           74,
		xdpDrops:      14,
		lsmHooks:      402,
		bpfEventChan:  make(chan string, 100),
		cortexLogChan: make(chan string, 100),
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

// --- Background Workers ---
func tailCortexLog(out chan string) {
	file, err := os.Open(CortexLog)
	if err != nil {
		out <- fmt.Sprintf("Error: %v", err)
		return
	}
	defer file.Close()

	file.Seek(0, 2)
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
				out <- safeText.Render(fmt.Sprintf("intent_decl cortex (%s)", strings.TrimSpace(parts[1])))
			}
		} else if strings.Contains(line, "✅ Intent APPROVED") {
			out <- safeText.Render("network_gate OPEN")
		} else if strings.Contains(line, "❌ Intent DENIED") {
			out <- alertText.Render("intent_denied ⛔")
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
				if action == "exec_denied" || action == "exfil_blocked" {
					styledAction = alertText.Render(fmt.Sprintf("%s PID:%d ⛔", action, event.PID))
				} else if action == "taint_elevate" {
					styledAction = alertText.Render(fmt.Sprintf("%s PID:%d ⚠️", action, event.PID))
				} else {
					styledAction = dimText.Render(fmt.Sprintf("%s PID:%d", action, event.PID))
				}
				out <- styledAction
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
		safeText.Render("842 req/s"),
	))

	lsmCard := cardBorder.Render(fmt.Sprintf("%s\nINTERCEPTS %7s\nTAINTED %10s",
		cardTitle.Render("KERNEL (LSM)"),
		safeText.Render(fmt.Sprintf("%d ev/s", m.lsmHooks)),
		alertText.Render("2 ev/s"),
	))

	cardsRow := lipgloss.JoinHorizontal(lipgloss.Top, sysCard, "  ", netCard, "  ", lsmCard)

	// 3. THREAT ARENA (Process Table)
	arenaHead := fmt.Sprintf(" %s %s", arenaTitle.Render("THREAT ARENA"), arenaLine.Render(strings.Repeat("┈", 65)))

	table := fmt.Sprintf(`  PID      TARGET         INTEGRITY       STATE                ACTION
  1042     nginx          %s      %s         [ ALLOW ]
  3391     node           %s      %s         [ ALLOW ]
  8991   %s bash           %s       %s      [ BLOCKED ]
           └─► SECCOMP: sys_socket (TCP OUTBOUND)
           └─► LSM: bpf_file_open (signature match)`,
		safeText.Render("✓ Verified"), safeText.Render("🟢 LISTENING"),
		safeText.Render("✓ Verified"), safeText.Render("🟢 LISTENING"),
		headerStyle.Render("❯"), alertText.Render("✗ TAINTED "), alertText.Render("🔴 EXFILTRATING"),
	)

	// 4. LIVE TICKER
	tickerContent := ""
	if len(m.events) > 0 {
		var tickerParts []string
		start := len(m.events) - 4
		if start < 0 {
			start = 0
		}
		for i := start; i < len(m.events); i++ {
			tickerParts = append(tickerParts, m.events[i])
		}
		tickerContent = strings.Join(tickerParts, "  |  ")
	} else {
		tickerContent = dimText.Render("Waiting for live trace events...")
	}

	ticker := fmt.Sprintf("%s  %s",
		tickerPrefix.Render("LIVE ❯"),
		tickerContent,
	)

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
		ticker,
	)

	return baseStyle.Render(ui) + "\n"
}
