#!/usr/bin/env python3
"""
Telos Telemetry Dashboard (Textual TUI)
A highly polished, reactive Terminal UI for the Telos Runtime.
"""

import socket
import json
import asyncio
import os
from datetime import datetime

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, Log, DataTable, Static
from textual.reactive import reactive
from textual.worker import Worker, get_current_worker
from textual import work

EVENTS_SOCKET = "/var/run/telos_events.sock"
CORTEX_LOG = "/tmp/telos_cortex.log"

class TelemetrySparkline(Static):
    """A reactive sparkline for global stats."""
    def on_mount(self) -> None:
        self.bpf_blocks = 0
        self.intent_elevations = 0
        self.update_stats()

    def update_stats(self) -> None:
        # Beautiful mock sparklines that occasionally update
        import random
        spark1 = "".join(random.choices(" ▂▃▅▆▇█", k=10))
        spark2 = "".join(random.choices(" ▂▃▅▆▇█", k=10))
        
        content = f"""[bold cyan]SYSTEM TELEMETRY[/]
        
[#86efac]CPU Overhead:[/]  {spark1} 0.2%
[#86efac]Mem Overhead:[/]  {spark2} 14MB

[#f87171]BPF Blocks:[/]    {self.bpf_blocks}
[#c084fc]Elevations:[/]    {self.intent_elevations}
"""
        self.update(content)
        self.set_interval(1.0, self.update_stats)

class TelosTelemetryApp(App):
    CSS = """
    Screen {
        background: #000000;
    }
    Header {
        background: #001a33;
        color: #00E5FF;
        text-style: bold;
    }
    .box {
        border: round #00E5FF;
        padding: 1;
        height: 100%;
        background: #0a0a0a;
    }
    .alert-box {
        border: double #FF0033;
        background: #1a0000;
        padding: 1;
        height: 100%;
    }
    .log-panel-left {
        border: round #c084fc;
        height: 100%;
        background: #050510;
        width: 1fr;
    }
    .log-panel-right {
        border: round #86efac;
        height: 100%;
        background: #001000;
        width: 1fr;
    }
    #top-row {
        height: 30%;
    }
    #bottom-row {
        height: 70%;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("c", "clear_logs", "Clear Logs")
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical():
            with Horizontal(id="top-row"):
                yield TelemetrySparkline(classes="box", id="stats")
                yield DataTable(classes="box", id="process_table")
            with Horizontal(id="bottom-row"):
                yield Log(id="intent_stream", classes="log-panel-left")
                yield Log(id="bpf_stream", classes="log-panel-right")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "TELOS RUNTIME ENGINE"
        self.sub_title = "Host Defense Dashboard"
        
        # Setup Table
        table = self.query_one(DataTable)
        table.add_columns("PID", "Command", "Taint Status", "Action")
        table.add_row("1042", "cortex", "Clean", "Allow")
        table.add_row("8991", "bash", "Tainted (Net)", "Monitor")
        table.add_row("4201", "curl", "Tainted (File)", "Monitor")

        # Setup logs
        self.intent_log = self.query_one("#intent_stream", Log)
        self.bpf_log = self.query_one("#bpf_stream", Log)
        
        self.intent_log.write_line("[bold cyan]=== CORTEX AI CONTROL PLANE ===[/]")
        self.bpf_log.write_line("[bold green]=== eBPF DATA PLANE (EXEC ENFORCEMENTS) ===[/]")

        # Start background workers
        self.tail_cortex_log()
        self.stream_bpf_events()

    def action_clear_logs(self) -> None:
        """Clear both logs when 'c' is pressed."""
        self.intent_log.clear()
        self.bpf_log.clear()
        self.intent_log.write_line("[bold cyan]=== CORTEX AI CONTROL PLANE ===[/]")
        self.bpf_log.write_line("[bold green]=== eBPF DATA PLANE (EXEC ENFORCEMENTS) ===[/]")

    @work(thread=True)
    def tail_cortex_log(self) -> None:
        """Tail Cortex log to find Intent declarations and verdicts."""
        worker = get_current_worker()
        try:
            if not os.path.exists(CORTEX_LOG):
                open(CORTEX_LOG, 'a').close()
                
            with open(CORTEX_LOG, 'r') as f:
                f.seek(0, 2)
                while not worker.is_cancelled:
                    line = f.readline()
                    if not line:
                        import time
                        time.sleep(0.1)
                        continue
                    
                    line = line.strip()
                    if "[Intent]" in line:
                        parts = line.split("[Intent]", 1)
                        if len(parts) > 1:
                            msg = parts[1].strip()
                            self.app.call_from_thread(self.intent_log.write_line, f"[cyan]Declare:[/cyan] {msg}")
                    elif "✅ Intent APPROVED" in line:
                        self.app.call_from_thread(self.intent_log.write_line, f"[green]Network Gate:[/green] OPEN")
                    elif "❌ Intent DENIED" in line:
                        msg = line.split('DENIED:', 1)[-1].strip()
                        self.app.call_from_thread(self.intent_log.write_line, f"[red]Intent Denied:[/red] {msg}")
                    elif "Exec Drawbridge locked to" in line:
                        bins = line.split("locked to:", 1)[-1].strip()
                        self.app.call_from_thread(self.intent_log.write_line, f"[bold cyan]Exec Gate:[/bold cyan] LOCKED {bins}")
                    elif "Exec Drawbridge locked COMPLETELY" in line:
                        self.app.call_from_thread(self.intent_log.write_line, f"[bold red]Exec Gate:[/bold red] LOCKED COMPLETELY (Deny All)")
        except Exception as e:
            self.app.call_from_thread(self.intent_log.write_line, f"[red]Error tailing log: {e}[/red]")

    @work(thread=True)
    def stream_bpf_events(self) -> None:
        """Connect to Go Loader Unix socket and stream BPF events."""
        worker = get_current_worker()
        while not worker.is_cancelled:
            try:
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.connect(EVENTS_SOCKET)
                f = client.makefile('r')
                self.app.call_from_thread(self.bpf_log.write_line, "[dim]Connected to BPF Events Stream...[/dim]")
                
                for line in f:
                    if worker.is_cancelled:
                        break
                    try:
                        event = json.loads(line)
                        action = event.get('desc', 'unknown')
                        pid = event.get('pid', 0)
                        taint = event.get('taint_level', 0)
                        
                        if action == "exec_denied":
                            color = "#f87171"
                            msg = f"✗ Blocked Exec"
                            self.app.call_from_thread(self.increment_bpf_blocks)
                        elif action == "open_inode":
                            color = "#fde047"
                            msg = f"! Sensitive File Opened"
                        elif action == "taint_elevate":
                            color = "#c084fc"
                            msg = f"↑ Taint Elevated"
                            self.app.call_from_thread(self.increment_elevations)
                        elif action == "exfil_blocked":
                            color = "#f87171"
                            msg = f"✗ Exfiltration Blocked"
                            self.app.call_from_thread(self.increment_bpf_blocks)
                        else:
                            color = "#6b7280"
                            msg = f"• {action}"
                            
                        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                        formatted = f"[{color}][{ts}] PID:{pid:<5} Taint:{taint} | {msg}[/]"
                        self.app.call_from_thread(self.bpf_log.write_line, formatted)
                        
                    except json.JSONDecodeError:
                        continue
                        
            except FileNotFoundError:
                import time
                if not worker.is_cancelled:
                    time.sleep(2)
            except Exception as e:
                import time
                if not worker.is_cancelled:
                    time.sleep(2)

    def increment_bpf_blocks(self):
        stats = self.query_one("#stats", TelemetrySparkline)
        stats.bpf_blocks += 1

    def increment_elevations(self):
        stats = self.query_one("#stats", TelemetrySparkline)
        stats.intent_elevations += 1

if __name__ == "__main__":
    app = TelosTelemetryApp()
    app.run()
