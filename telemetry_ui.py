#!/usr/bin/env python3
"""
Telos Telemetry Dashboard (Phase 7)
Live split-screen terminal UI showing AI Intents vs. eBPF Kernel Enforcements.
"""

import socket
import json
import threading
import time
import sys
from datetime import datetime
from collections import deque


from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich import box

EVENTS_SOCKET = "/var/run/telos_events.sock"
MAX_EVENTS = 20

# We don't have a direct stream for intents yet, but we can tail the cortex log
# For a true polished demo, Cortex could also stream its intents to a socket,
# but parsing the log file is simple and effective.
CORTEX_LOG = "/tmp/telos_cortex.log"

# Global state
bpf_events = deque(maxlen=MAX_EVENTS)
intent_events = deque(maxlen=MAX_EVENTS)
stats = {"allowed": 0, "denied": 0, "elevated": 0}

console = Console()

def tail_cortex_log():
    """Tail Cortex log to find Intent declarations and verdicts."""
    try:
        # Standard tail -f logic
        with open(CORTEX_LOG, 'r') as f:
            f.seek(0, 2) # Go to end
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                line = line.strip()
                if "[Intent]" in line:
                    # Example: 2026-02-20 22:45:01 [INFO] telos.cortex: [Intent] Agent 1234: Download docs
                    parts = line.split("[Intent]", 1)
                    if len(parts) > 1:
                        msg = parts[1].strip()
                        intent_events.appendleft(f"[cyan]Declare:[/cyan] {msg}")
                elif "✅ Intent APPROVED" in line:
                    intent_events.appendleft(f"[green]Network Gate:[/green] OPEN")
                elif "❌ Intent DENIED" in line:
                    intent_events.appendleft(f"[red]Intent Denied:[/red] {line.split('DENIED:', 1)[-1].strip()}")
                elif "[EI]" in line:
                    parts = line.split("[EI]", 1)[-1].strip()
                    if "ALLOW" in parts or "VERIFIED" in parts:
                        intent_events.appendleft(f"[green]Exec Intel (L4):[/green] {parts}")
                    elif "DENY" in parts or "DENIED" in parts:
                        intent_events.appendleft(f"[red]Exec Intel (L2/L3):[/red] {parts}")
                    else:
                        intent_events.appendleft(f"[yellow]Exec Intel:[/yellow] {parts}")
                elif "Exec Drawbridge locked to" in line:
                    bins = line.split("locked to:", 1)[-1].strip()
                    intent_events.appendleft(f"[bold cyan]Exec Gate:[/bold cyan] LOCKED {bins}")
                elif "Exec Drawbridge locked COMPLETELY" in line:
                    intent_events.appendleft(f"[bold red]Exec Gate:[/bold red] LOCKED COMPLETELY (Deny All)")
    except Exception as e:
        intent_events.appendleft(f"[red]Error tailing log: {e}[/red]")

def stream_bpf_events():
    """Connect to Go Loader Unix socket and stream BPF events."""
    while True:
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(EVENTS_SOCKET)
            f = client.makefile('r')
            bpf_events.appendleft("[dim]Connected to BPF Events Stream...[/dim]")
            
            for line in f:
                try:
                    event = json.loads(line)
                    # { timestamp, pid, taint_level, action, desc }
                    
                    action = event.get('desc', 'unknown')
                    pid = event.get('pid', 0)
                    taint = event.get('taint_level', 0)
                    
                    # Formatting based on event type
                    if action == "exec_denied":
                        color = "red"
                        stats["denied"] += 1
                        msg = f"✗ Blocked Exec"
                    elif action == "open_inode":
                        color = "yellow"
                        msg = f"! Sensitive File Opened"
                    elif action == "taint_elevate":
                        color = "magenta"
                        stats["elevated"] += 1
                        msg = f"↑ Taint Elevated"
                    elif action == "exfil_blocked":
                        color = "red"
                        stats["denied"] += 1
                        msg = f"✗ Exfiltration Blocked (IFC)"
                    else:
                        color = "dim"
                        msg = f"• {action}"
                        
                    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                    formatted = f"[{color}][{ts}] PID:{pid:<5} Taint:{taint} | {msg}[/{color}]"
                    bpf_events.appendleft(formatted)
                    
                except json.JSONDecodeError:
                    continue
                    
        except FileNotFoundError:
            bpf_events.appendleft(f"[red]Socket {EVENTS_SOCKET} not found. Core running?[/red]")
            time.sleep(2)
        except Exception as e:
            bpf_events.appendleft(f"[red]Stream error: {e}[/red]")
            time.sleep(2)

def generate_layout() -> Layout:
    """Create the rich standard layout."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3)
    )
    layout["body"].split_row(
        Layout(name="left", ratio=1),
        Layout(name="right", ratio=1)
    )
    return layout

def get_intents_panel() -> Panel:
    text = "\n".join(list(intent_events))
    return Panel(
        Text.from_markup(text), 
        title="[bold cyan]Cortex AI Control Plane (Intents & Network)[/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED
    )

def get_bpf_panel() -> Panel:
    text = "\n".join(list(bpf_events))
    return Panel(
        Text.from_markup(text), 
        title="[bold green]eBPF Kernel Data Plane (Execution Enforcements)[/bold green]",
        border_style="green",
        box=box.ROUNDED
    )

def get_header() -> Panel:
    grid = Table.grid(expand=True)
    grid.add_column(justify="left", ratio=1)
    grid.add_column(justify="center", ratio=1)
    grid.add_column(justify="right", ratio=1)
    grid.add_row(
        "Dual-Gate Architecture", 
        "[bold magenta]TELOS TELEMETRY DASHBOARD[/bold magenta]", 
        datetime.now().strftime("%c")
    )
    return Panel(grid, style="white on black", box=box.SIMPLE)

def get_footer() -> Panel:
    text = f"[bold]Stats:[/bold] BPF Blocks: [red]{stats['denied']}[/red] | Taint Elevations: [magenta]{stats['elevated']}[/magenta] | Status: [green]LIVE[/green]"
    return Panel(Text.from_markup(text, justify="center"), style="white on black", box=box.SIMPLE)

def main():
    # Start background threads
    t1 = threading.Thread(target=tail_cortex_log, daemon=True)
    t2 = threading.Thread(target=stream_bpf_events, daemon=True)
    t1.start()
    t2.start()

    layout = generate_layout()
    
    with Live(layout, refresh_per_second=10, screen=True):
        while True:
            try:
                layout["header"].update(get_header())
                layout["left"].update(get_intents_panel())
                layout["right"].update(get_bpf_panel())
                layout["footer"].update(get_footer())
                time.sleep(0.1)
            except KeyboardInterrupt:
                break

if __name__ == "__main__":
    main()
