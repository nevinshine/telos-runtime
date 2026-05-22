#!/usr/bin/env python3
"""
Telos Runtime CLI — Bubbletea-style TUI Orchestrator

A beautiful terminal interface for managing the Telos Runtime Security Engine,
inspired by Charm's Bubbletea/Lipgloss framework. Uses Rich for rendering.
"""

import os
import sys
import time
import signal
import subprocess
import shutil

from pathlib import Path

# ── Rich Imports ─────────────────────────────────────────────────────────────

from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.table import Table
from rich.columns import Columns
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
)
from rich.style import Style
from rich.align import Align
from rich import box

# ── Constants ────────────────────────────────────────────────────────────────

VERSION = "0.5.0"
PROJECT_DIR = Path(__file__).resolve().parent
LOG_DIR = PROJECT_DIR / "logs"
DAEMON_LOG = LOG_DIR / "telos_daemon.log"
CORTEX_LOG = LOG_DIR / "telos_cortex.log"
DAEMON_PID_FILE = Path("/tmp/telos_daemon.pid")
CORTEX_PID_FILE = Path("/tmp/telos_cortex.pid")
BPF_PIN_PATH = Path("/sys/fs/bpf/telos")

# ── Palette (Lipgloss-inspired) ──────────────────────────────────────────────

PINK = "#ff6b9d"
PURPLE = "#c084fc"
CYAN = "#67e8f9"
GREEN = "#86efac"
RED = "#f87171"
YELLOW = "#fde047"
DIM = "#6b7280"
WHITE = "#f9fafb"
SURFACE = "#1e1e2e"

console = Console()


# ── Header ───────────────────────────────────────────────────────────────────

def print_header():
    """Print the Telos branded header with gradient styling."""
    # Build gradient title
    title = Text()
    gradient_chars = "T E L O S"
    colors = ["#c084fc", "#a78bfa", "#818cf8", "#6366f1", "#7c3aed",
              "#6d28d9", "#5b21b6", "#7c3aed", "#6366f1"]
    for i, ch in enumerate(gradient_chars):
        title.append(ch, style=Style(color=colors[i % len(colors)], bold=True))

    subtitle = Text("Runtime Security Engine", style=Style(color=DIM))
    version_text = Text(f"v{VERSION}", style=Style(color=DIM, italic=True))

    # Compose header content
    header_content = Text()
    header_content.append_text(title)
    header_content.append("  ")
    header_content.append_text(version_text)
    header_content.append("\n")
    header_content.append_text(subtitle)

    panel = Panel(
        header_content,
        border_style=Style(color=PURPLE),
        box=box.ROUNDED,
        padding=(0, 2),
        expand=False,
    )
    console.print()
    console.print(panel)
    console.print()


# ── Process Helpers ──────────────────────────────────────────────────────────

def pid_alive(pid_file: Path) -> int | None:
    """Return PID if alive, None otherwise."""
    if not pid_file.exists():
        return None
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, 0)
        return pid
    except (ValueError, ProcessLookupError, PermissionError):
        return None


def run_step(cmd: str, cwd: str = str(PROJECT_DIR)) -> bool:
    """Run a shell command, return True on success."""
    result = subprocess.run(
        cmd, shell=True, cwd=cwd,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    return result.returncode == 0


# ── Start Command ────────────────────────────────────────────────────────────

def cmd_start(extra_args: list[str]):
    """Build and start the Telos Runtime with animated progress."""
    if os.geteuid() != 0:
        console.print(f"  [bold {RED}]✕[/]  Please run as root (use sudo).")
        sys.exit(1)

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # Honor TELOS_SOCKET_PATH env var by injecting --socket if not already specified
    socket_path = os.environ.get("TELOS_SOCKET_PATH", "")
    if socket_path and "--socket" not in extra_args:
        extra_args = ["--socket", socket_path] + extra_args

    args_str = " ".join(extra_args)

    console.print(f"\n[bold {PURPLE}]telos[/]   [dim]v2.0.0[/]\n")

    # 1. Build eBPF Core
    start_t = time.time()
    if not run_step("make bpf"):
        console.print(f"[{RED}]✕[/] Failed to build eBPF Core")
        sys.exit(1)
    ms = int((time.time() - start_t) * 1000)
    console.print(f"[{DARK_GRAY}]│[/]")
    console.print(f"[{GREEN}]▶[/]  {'eBPF Core compiled':<35} [dim]{ms}ms[/]")

    # 2. Build Go Loader
    start_t = time.time()
    if not run_step("make loader"):
        console.print(f"[{RED}]✕[/] Failed to build Go Loader")
        sys.exit(1)
    ms = int((time.time() - start_t) * 1000)
    console.print(f"[{DARK_GRAY}]│[/]")
    console.print(f"[{GREEN}]▶[/]  {'Go Loader built':<35} [dim]{ms}ms[/]")

    # 3. Daemon
    start_t = time.time()
    daemon_pid = pid_alive(DAEMON_PID_FILE)
    if not daemon_pid:
        DAEMON_LOG.unlink(missing_ok=True)
        proc = subprocess.Popen(
            ["./bin/telos_daemon"] + extra_args,
            cwd=str(PROJECT_DIR),
            stdin=subprocess.DEVNULL,
            stdout=open(DAEMON_LOG, "w"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        DAEMON_PID_FILE.write_text(str(proc.pid))
        daemon_pid = proc.pid
    
    # Give daemon a tiny moment to bind socket
    time.sleep(0.5)
    ms = int((time.time() - start_t) * 1000)
    console.print(f"[{DARK_GRAY}]│[/]")
    console.print(f"[{GREEN}]▶[/]  {'Sentinel LSM hooks loaded':<35} [dim]{ms}ms[/]")

    # 4. Cortex
    start_t = time.time()
    cortex_pid = pid_alive(CORTEX_PID_FILE)
    if not cortex_pid:
        CORTEX_LOG.unlink(missing_ok=True)
        sudo_user = os.environ.get("SUDO_USER", os.environ.get("USER", "root"))
        user_packages = f"/home/{sudo_user}/.local/lib/python3.14/site-packages"
        cortex_token = os.environ.get("TELOS_CORTEX_AUTH_TOKEN", "telos-dev-token")

        env = os.environ.copy()
        env["PYTHONPATH"] = f"{user_packages}:{env.get('PYTHONPATH', '')}"
        env["TELOS_CORTEX_LOG"] = str(CORTEX_LOG)
        env["TELOS_CORTEX_AUTH_TOKEN"] = cortex_token

        proc = subprocess.Popen(
            ["python3", "cortex/main.py"] + extra_args,
            cwd=str(PROJECT_DIR),
            stdin=subprocess.DEVNULL,
            stdout=open(CORTEX_LOG, "w"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=env,
        )
        CORTEX_PID_FILE.write_text(str(proc.pid))
        cortex_pid = proc.pid
    ms = int((time.time() - start_t) * 1000)
    console.print(f"[{DARK_GRAY}]│[/]")
    console.print(f"[{GREEN}]▶[/]  {'Cortex daemon synchronized':<35} [dim]{ms}ms[/]")

    console.print(f"[{DARK_GRAY}]│[/]")
    console.print(f"[{GREEN}]▶[/]  Liftoff confirmed. Securing runtime boundary!\n")

    # Summary panel
    console.print()

    # Wait a moment for Cortex to boot and check its log
    time.sleep(1.5)
    cortex_port = "50051"
    if CORTEX_LOG.exists():
        log_content = CORTEX_LOG.read_text()
        # Extract port from log
        import re
        port_match = re.search(r"gRPC.*?:(\d+)", log_content)
        if port_match:
            cortex_port = port_match.group(1)

    summary = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
        show_edge=False,
    )
    summary.add_column(style=Style(color=DIM))
    summary.add_column(style=Style(color=WHITE, bold=True))
    summary.add_column(style=Style(color=CYAN))

    summary.add_row("┃", "gRPC", f"grpc://127.0.0.1:{cortex_port}")
    summary.add_row("┃", "DNS", "udp://127.0.0.1:5353")
    socket_display = os.environ.get("TELOS_SOCKET_PATH", "/var/run/telos.sock")
    for i, a in enumerate(extra_args):
        if a == "--socket" and i + 1 < len(extra_args):
            socket_display = extra_args[i + 1]
            break
    summary.add_row("┃", "IPC", socket_display)
    summary.add_row("┃", "Dashboard", "run: ./telos dash")
    summary.add_row("┃", "Daemon Log", str(DAEMON_LOG))
    summary.add_row("┃", "Cortex Log", str(CORTEX_LOG))

    console.print(f"  [{GREEN}][bold]Telos is now running.[/][/]")
    console.print()
    console.print(summary)
    console.print()


# ── Stop Command ─────────────────────────────────────────────────────────────

def cmd_stop():
    """Stop all Telos processes with animated feedback."""
    if os.geteuid() != 0:
        console.print(f"  [bold {RED}]✕[/]  Please run as root (use sudo).")
        sys.exit(1)

    console.print(f"\n[bold {PURPLE}]telos[/]   [dim]v2.0.0[/]\n")

    # Stop Cortex
    start_t = time.time()
    cortex_pid = pid_alive(CORTEX_PID_FILE)
    if cortex_pid:
        os.kill(cortex_pid, signal.SIGTERM)
        time.sleep(1)
        try:
            os.kill(cortex_pid, 0)
            os.kill(cortex_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    CORTEX_PID_FILE.unlink(missing_ok=True)
    ms = int((time.time() - start_t) * 1000)
    console.print(f"[{DARK_GRAY}]│[/]")
    console.print(f"[{GREEN}]▶[/]  {'Cortex daemon halted':<35} [dim]{ms}ms[/]")

    # Stop Daemon
    start_t = time.time()
    daemon_pid = pid_alive(DAEMON_PID_FILE)
    if daemon_pid:
        os.kill(daemon_pid, signal.SIGTERM)
        time.sleep(2)
        try:
            os.kill(daemon_pid, 0)
            os.kill(daemon_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        console.print(f"  [{GREEN}]●[/]  [white]Daemon stopped[/]  [{DIM}]PID: {daemon_pid}[/]")
    else:
        console.print(f"  [{YELLOW}]●[/]  [white]Daemon[/]  [{DIM}]not running[/]")
    DAEMON_PID_FILE.unlink(missing_ok=True)

    # Cleanup BPF
    if BPF_PIN_PATH.exists():
        # Check if mounted
        subprocess.run(
            f"mountpoint -q '{BPF_PIN_PATH}' && umount '{BPF_PIN_PATH}'",
            shell=True, stderr=subprocess.DEVNULL
        )
        shutil.rmtree(BPF_PIN_PATH, ignore_errors=True)
    console.print(f"  [{GREEN}]●[/]  [white]BPF maps cleaned[/]")

    console.print()
    console.print(f"  [{GREEN}][bold]Telos stopped.[/][/]")
    console.print()


# ── Status Command ───────────────────────────────────────────────────────────

def cmd_status():
    """Show runtime status with a styled table."""
    table = Table(
        show_header=True,
        header_style=Style(color=PURPLE, bold=True),
        box=box.ROUNDED,
        border_style=Style(color="#374151"),
        padding=(0, 2),
        expand=False,
    )
    table.add_column("Component", style=Style(color=WHITE, bold=True))
    table.add_column("Status", justify="center")
    table.add_column("Details", style=Style(color=DIM))

    # Daemon
    daemon_pid = pid_alive(DAEMON_PID_FILE)
    if daemon_pid:
        table.add_row(
            "Telos Daemon",
            Text("● RUNNING", style=Style(color=GREEN, bold=True)),
            f"PID: {daemon_pid}"
        )
    else:
        table.add_row(
            "Telos Daemon",
            Text("● STOPPED", style=Style(color=RED, bold=True)),
            "—"
        )

    # Cortex
    cortex_pid = pid_alive(CORTEX_PID_FILE)
    if cortex_pid:
        table.add_row(
            "Telos Cortex",
            Text("● RUNNING", style=Style(color=GREEN, bold=True)),
            f"PID: {cortex_pid}"
        )
    else:
        table.add_row(
            "Telos Cortex",
            Text("● STOPPED", style=Style(color=RED, bold=True)),
            "—"
        )

    # BPF Maps
    bpf_exists = BPF_PIN_PATH.exists() and any(BPF_PIN_PATH.iterdir()) if BPF_PIN_PATH.exists() else False
    if bpf_exists:
        table.add_row(
            "BPF Maps",
            Text("● PINNED", style=Style(color=GREEN, bold=True)),
            str(BPF_PIN_PATH)
        )
    else:
        table.add_row(
            "BPF Maps",
            Text("● NOT FOUND", style=Style(color=RED, bold=True)),
            "—"
        )

    # Dashboard
    dash_running = pid_alive(Path("/tmp/telos_tui.pid"))
    if dash_running:
        table.add_row(
            "Terminal UI",
            Text("● RUNNING", style=Style(color=GREEN, bold=True)),
            f"PID: {dash_running}"
        )
    else:
        table.add_row(
            "Terminal UI",
            Text("● STOPPED", style=Style(color=RED, bold=True)),
            "run: ./telos dash"
        )

    console.print(table)
    console.print()


# ── Help Command ─────────────────────────────────────────────────────────────

def cmd_help():
    """Print styled help text."""
    # Commands table
    table = Table(
        show_header=False,
        box=None,
        padding=(0, 1),
        show_edge=False,
    )
    table.add_column(min_width=12)
    table.add_column()

    table.add_row(
        Text("start", style=Style(color=GREEN, bold=True)),
        Text("Build and start the Telos Daemon and Cortex AI", style=Style(color=WHITE))
    )
    table.add_row(
        Text("stop", style=Style(color=RED, bold=True)),
        Text("Stop all processes and clean eBPF maps", style=Style(color=WHITE))
    )
    table.add_row(
        Text("status", style=Style(color=CYAN, bold=True)),
        Text("Display runtime status of all components", style=Style(color=WHITE))
    )
    table.add_row(
        Text("dash", style=Style(color=PURPLE, bold=True)),
        Text("Launch the live Telemetry UI dashboard", style=Style(color=WHITE))
    )
    table.add_row(
        Text("help", style=Style(color=DIM, bold=True)),
        Text("Show this message", style=Style(color=WHITE))
    )

    usage = Text()
    usage.append("USAGE", style=Style(bold=True, color=WHITE))
    usage.append("  sudo ./telos ", style=Style(color=DIM))
    usage.append("<command>", style=Style(color=PURPLE, bold=True))
    usage.append(" [args...]", style=Style(color=DIM))

    console.print(f"  {usage}")
    console.print()

    cmd_panel = Panel(
        table,
        title=Text("Commands", style=Style(color=PURPLE, bold=True)),
        border_style=Style(color="#374151"),
        box=box.ROUNDED,
        padding=(1, 2),
        expand=False,
    )
    console.print(cmd_panel)

    # Examples
    console.print()
    console.print(f"  [bold white]Examples[/]")
    console.print(f"  [{DIM}]$[/] [white]sudo ./telos start[/]              [{DIM}]# Start with defaults[/]")
    console.print(f"  [{DIM}]$[/] [white]sudo ./telos start --port 50055[/] [{DIM}]# Custom gRPC port[/]")
    console.print(f"  [{DIM}]$[/] [white]sudo ./telos status[/]             [{DIM}]# Check what's running[/]")
    console.print(f"  [{DIM}]$[/] [white]./telos dash[/]                   [{DIM}]# Launch Terminal UI[/]")
    console.print()


# ── Dash Command ─────────────────────────────────────────────────────────────

def cmd_dash():
    """Launch the TUI telemetry dashboard."""
    tui_dir = PROJECT_DIR / "telos_tui"
    tui_bin = tui_dir / "bin" / "telos_tui"

    # Build if it doesn't exist
    if not tui_bin.exists():
        console.print(f"  [{YELLOW}]●[/]  [white]Building Go TUI...[/]")
        success = run_step("go build -o bin/telos_tui", cwd=str(tui_dir))
        if not success:
            console.print(f"  [{RED}]✕[/]  Failed to build TUI")
            sys.exit(1)

    # Write PID so status can find it, though it's foreground
    Path("/tmp/telos_tui.pid").write_text(str(os.getpid()))
    try:
        os.execv(str(tui_bin), [str(tui_bin)])
    finally:
        Path("/tmp/telos_tui.pid").unlink(missing_ok=True)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print_header()
        cmd_help()
        sys.exit(1)

    command = sys.argv[1]
    extra = sys.argv[2:]

    if command in ("start", "stop", "status", "help"):
        print_header()

    if command == "start":
        cmd_start(extra)
    elif command == "stop":
        cmd_stop()
    elif command == "status":
        cmd_status()
    elif command == "dash":
        cmd_dash()
    elif command == "help":
        cmd_help()
    else:
        print_header()
        console.print(f"  [{RED}]✕[/]  Unknown command: [bold]{command}[/]")
        console.print()
        cmd_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
