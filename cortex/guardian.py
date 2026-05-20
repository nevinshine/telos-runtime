"""
Telos Guardian - Intent Verification Engine

Manages:
1. Agent Registry (PID tracking)
2. Taint State (per-source and per-agent)
3. Policy Decisions
4. PID Bridge (mapping browser views to agents)
"""

import logging
import threading
import time
from typing import Dict, Optional, Set
from dataclasses import dataclass, field

log = logging.getLogger('telos.guardian')


@dataclass
class TaintRecord:
    """Record of taint for a specific source/view."""
    source_id: str
    level: int
    url: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class AgentInfo:
    """Information about a registered agent."""
    pid: int
    registered_at: float = field(default_factory=time.time)
    taint_level: int = 0
    active_views: Set[str] = field(default_factory=set)  # source_ids being viewed


class Guardian:
    """
    The Guardian manages security state and policy decisions.

    PID Bridge Logic:
    - Agents register their PID when starting
    - When a browser view reports taint, we map it to the active agent
    - For Phase 2: Simple model assumes single active agent
    - Future: Session ID mapping, multiple agents
    """

    def __init__(self, policy: dict):
        self._policy = policy
        self._lock = threading.RLock()

        # Agent registry: PID -> AgentInfo
        self._agents: Dict[int, AgentInfo] = {}

        # Explicit registration-order tracking for deterministic active-agent selection.
        # The last element is the most recently registered agent.
        self._registration_order: list[int] = []

        # Active agent (for simple Phase 2 model)
        self._active_agent_pid: Optional[int] = None

        # Taint records: source_id -> TaintRecord
        self._taint_records: Dict[str, TaintRecord] = {}

        # View to Agent mapping: source_id -> PID
        self._view_agent_map: Dict[str, int] = {}

        # Session ID mapping: session_id -> PID
        self.session_map: Dict[str, int] = {}

        # Kernel-taint snapshot: PID -> taint_level
        # Used to avoid losing taint state across control-plane re-declarations.
        self.core_taint: Dict[int, int] = {}
        
        log.info("Guardian initialized")

    # === AGENT REGISTRY ===

    def get_session_pid(self, session_id: str) -> Optional[int]:
        """Return the PID bound to a session ID, or None."""
        if not session_id:
            return None
        with self._lock:
            return self._session_map.get(session_id)

    def register_session(self, session_id: str, pid: int) -> bool:
        """Register a session ID for an agent."""
        if not session_id:
            return False
        with self._lock:
            self._session_map[session_id] = pid
        log.info(f"Session mapped: {session_id[:8]}... -> PID {pid}")
        return True

    def register_agent(self, pid: int) -> bool:
        """
        Register an agent process.

        In Phase 2, the most recently registered agent is considered "active"
        and will receive taint from browser views.
        """
        with self._lock:
            if pid in self._agents:
                log.debug(f"Agent {pid} already registered")
                return True

            self._agents[pid] = AgentInfo(pid=pid)
            self._registration_order.append(pid)
            self._active_agent_pid = pid  # Most recent becomes active

        log.info(f"[+] Agent registered: PID {pid}")
        return True
    
    def unregister_agent(self, pid: int) -> bool:
        """Unregister an agent when it exits."""
        if pid not in self.agents:
            return False
        
        del self.agents[pid]
        
        # Clean session map
        for sid, p in list(self.session_map.items()):
            if p == pid:
                del self.session_map[sid]
        
        # Update active agent
        if self.active_agent_pid == pid:
            if self.agents:
                self.active_agent_pid = list(self.agents.keys())[-1]
            else:
                self.active_agent_pid = None
        
        # Clean up view mappings
        for source_id, mapped_pid in list(self.view_agent_map.items()):
            if mapped_pid == pid:
                del self.view_agent_map[source_id]

        if pid in self.core_taint:
            del self.core_taint[pid]
            
        log.info(f"[-] Agent unregistered: PID {pid}")
        return True

    # === TAINT MANAGEMENT ===

    def update_taint(self, source_id: str, level: int, url: str = "", session_id: str = "") -> None:
        """
        Update taint record for a browser view/source.

        Args:
            source_id: Browser tab/view identifier
            level: TaintLevel enum value (0-4)
            url: URL where taint was detected
            session_id: Optional session ID from browser
        """
        with self._lock:
            self._taint_records[source_id] = TaintRecord(
                source_id=source_id,
                level=level,
                url=url
            )

            # Also update the associated agent's taint level
            agent_pid = self._get_agent_pid_for_view_unlocked(source_id, session_id)
            if agent_pid and agent_pid in self._agents:
                # Agent's taint is the max of all their views
                current_max = self._agents[agent_pid].taint_level
                if level > current_max:
                    self._agents[agent_pid].taint_level = level
                    log.warning(f"Agent {agent_pid} taint escalated to {level}")

    def get_taint_level(self, pid: int) -> int:
        """Get current taint level for an agent PID."""
        core_level = self.core_taint.get(pid, 0)
        if pid in self.agents:
            return max(self.agents[pid].taint_level, core_level)
        if core_level:
            return core_level
        return 0  # CLEAN for unknown processes

    def update_core_taint(self, pid: int, taint_level: int) -> None:
        """Record the latest kernel taint snapshot for a PID."""
        if pid <= 0:
            return
        current = self.core_taint.get(pid, 0)
        if taint_level > current:
            self.core_taint[pid] = taint_level
    
    def clear_taint(self, pid: int) -> None:
        """Reset taint level for an agent (after cooldown/verification)."""
        if pid in self.agents:
            self.agents[pid].taint_level = 0
            if pid in self.core_taint:
                self.core_taint[pid] = 0
            log.info(f"Taint cleared for agent {pid}")
    
    # === PID BRIDGE ===

    def get_agent_pid_for_view(self, source_id: str, session_id: str = "") -> Optional[int]:
        """
        Resolve which agent PID should receive taint from a browser view.

        Strategy:
        1. Check explicit session_id mapping (Phase 3)
        2. Check explicit source_id mapping
        3. Fall back to active agent (Phase 2 legacy)
        """
        with self._lock:
            return self._get_agent_pid_for_view_unlocked(source_id, session_id)

    def _get_agent_pid_for_view_unlocked(self, source_id: str, session_id: str = "") -> Optional[int]:
        """Internal unlocked version � caller must hold self._lock."""
        # 1. Session ID (Strongest Link)
        if session_id and session_id in self._session_map:
            pid = self._session_map[session_id]
            # Auto-map for future lookups without session_id
            self._view_agent_map[source_id] = pid
            return pid

        # 2. Check explicit view mapping
        if source_id in self._view_agent_map:
            return self._view_agent_map[source_id]

        # 3. Fall back to active agent (Migration/Legacy)
        if self._active_agent_pid:
            # Auto-map this view to the active agent
            self._view_agent_map[source_id] = self._active_agent_pid
            if self._active_agent_pid in self._agents:
                self._agents[self._active_agent_pid].active_views.add(source_id)
            return self._active_agent_pid

        return None

    def map_view_to_agent(self, source_id: str, pid: int) -> bool:
        """Explicitly map a browser view to an agent."""
        with self._lock:
            if pid not in self._agents:
                log.warning(f"Cannot map view to unknown agent {pid}")
                return False

            self._view_agent_map[source_id] = pid
            self._agents[pid].active_views.add(source_id)
            log.debug(f"View {source_id} mapped to agent {pid}")
            return True

    # === POLICY ===

    def get_policy(self) -> dict:
        """Return current policy configuration."""
        return self._policy

    def should_block_exec(self, pid: int) -> bool:
        """
        Determine if a process should be blocked from executing commands.

        Returns True if taint level exceeds policy threshold.
        """
        max_taint = self._policy.get('max_taint_for_exec', 2)  # Default: MEDIUM
        with self._lock:
            current_taint = self._agents[pid].taint_level if pid in self._agents else 0

        if current_taint > max_taint:
            log.warning(f"BLOCK: Agent {pid} exceeds taint threshold ({current_taint} > {max_taint})")
            return True
        return False

    # === DEBUG ===

    def get_state_summary(self) -> dict:
        """Get a summary of current guardian state for debugging."""
        with self._lock:
            return {
                'agents': {
                    pid: {
                        'taint_level': info.taint_level,
                        'active_views': list(info.active_views),
                        'registered_at': info.registered_at
                    }
                    for pid, info in self._agents.items()
                },
                'active_agent': self._active_agent_pid,
                'taint_records': {
                    sid: {
                        'level': rec.level,
                        'url': rec.url,
                        'age_seconds': time.time() - rec.timestamp
                    }
                    for sid, rec in self._taint_records.items()
                }
            }

    # === LOCKED ACCESSORS (thread-safe snapshots) ===

    def get_agent_pids(self):
        """Return a snapshot list of registered agent PIDs."""
        with self._lock:
            return list(self._agents.keys())

    def get_agent_count(self) -> int:
        """Return the number of registered agents."""
        with self._lock:
            return len(self._agents)

    def has_agent(self, pid: int) -> bool:
        """Check if an agent PID is registered (thread-safe)."""
        with self._lock:
            return pid in self._agents

    def get_active_agent_pid(self):
        """Return the active agent PID, or None (thread-safe)."""
        with self._lock:
            return self._active_agent_pid

    def get_taint_record_count(self) -> int:
        """Return the number of taint records (thread-safe)."""
        with self._lock:
            return len(self._taint_records)

    def get_session_count(self) -> int:
        """Return the number of registered session mappings (thread-safe)."""
        with self._lock:
            return len(self._session_map)

    def get_session_map_snapshot(self):
        """Return a thread-safe shallow copy of the session map."""
        with self._lock:
            return dict(self._session_map)

