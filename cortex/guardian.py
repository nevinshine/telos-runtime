"""
Telos Guardian - Intent Verification Engine

Manages:
1. Agent Registry (PID tracking)
2. Taint State (per-source and per-agent)
3. Policy Decisions
4. PID Bridge (mapping browser views to agents)
"""

import logging
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
        self.policy = policy
        
        # Agent registry: PID -> AgentInfo
        self.agents: Dict[int, AgentInfo] = {}
        
        # Active agent (for simple Phase 2 model)
        self.active_agent_pid: Optional[int] = None
        
        # Taint records: source_id -> TaintRecord
        self.taint_records: Dict[str, TaintRecord] = {}
        
        # View to Agent mapping: source_id -> PID
        self.view_agent_map: Dict[str, int] = {}
        
        log.info("Guardian initialized")
    
    # === AGENT REGISTRY ===
    
    def register_agent(self, pid: int) -> bool:
        """
        Register an agent process.
        
        In Phase 2, the most recently registered agent is considered "active"
        and will receive taint from browser views.
        """
        if pid in self.agents:
            log.debug(f"Agent {pid} already registered")
            return True
        
        self.agents[pid] = AgentInfo(pid=pid)
        self.active_agent_pid = pid  # Most recent becomes active
        
        log.info(f"[+] Agent registered: PID {pid}")
        return True
    
    def unregister_agent(self, pid: int) -> bool:
        """Unregister an agent when it exits."""
        if pid not in self.agents:
            return False
        
        del self.agents[pid]
        
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
        
        log.info(f"[-] Agent unregistered: PID {pid}")
        return True
    
    # === TAINT MANAGEMENT ===
    
    def update_taint(self, source_id: str, level: int, url: str = "") -> None:
        """
        Update taint record for a browser view/source.
        
        Args:
            source_id: Browser tab/view identifier
            level: TaintLevel enum value (0-4)
            url: URL where taint was detected
        """
        self.taint_records[source_id] = TaintRecord(
            source_id=source_id,
            level=level,
            url=url
        )
        
        # Also update the associated agent's taint level
        agent_pid = self.get_agent_pid_for_view(source_id)
        if agent_pid and agent_pid in self.agents:
            # Agent's taint is the max of all their views
            current_max = self.agents[agent_pid].taint_level
            if level > current_max:
                self.agents[agent_pid].taint_level = level
                log.warning(f"Agent {agent_pid} taint escalated to {level}")
    
    def get_taint_level(self, pid: int) -> int:
        """Get current taint level for an agent PID."""
        if pid in self.agents:
            return self.agents[pid].taint_level
        return 0  # CLEAN for unknown processes
    
    def clear_taint(self, pid: int) -> None:
        """Reset taint level for an agent (after cooldown/verification)."""
        if pid in self.agents:
            self.agents[pid].taint_level = 0
            log.info(f"Taint cleared for agent {pid}")
    
    # === PID BRIDGE ===
    
    def get_agent_pid_for_view(self, source_id: str) -> Optional[int]:
        """
        Resolve which agent PID should receive taint from a browser view.
        
        Phase 2 Strategy (Simple):
        1. If source_id is explicitly mapped, use that mapping
        2. Otherwise, assume the active agent is viewing this source
        
        Phase 3+ Strategy:
        - Use session IDs passed from agent to browser
        - Track which agent opened which URLs
        """
        # Check explicit mapping first
        if source_id in self.view_agent_map:
            return self.view_agent_map[source_id]
        
        # Fall back to active agent
        if self.active_agent_pid:
            # Auto-map this view to the active agent
            self.view_agent_map[source_id] = self.active_agent_pid
            if self.active_agent_pid in self.agents:
                self.agents[self.active_agent_pid].active_views.add(source_id)
            return self.active_agent_pid
        
        return None
    
    def map_view_to_agent(self, source_id: str, pid: int) -> bool:
        """Explicitly map a browser view to an agent."""
        if pid not in self.agents:
            log.warning(f"Cannot map view to unknown agent {pid}")
            return False
        
        self.view_agent_map[source_id] = pid
        self.agents[pid].active_views.add(source_id)
        log.debug(f"View {source_id} mapped to agent {pid}")
        return True
    
    # === POLICY ===
    
    def get_policy(self) -> dict:
        """Return current policy configuration."""
        return self.policy
    
    def should_block_exec(self, pid: int) -> bool:
        """
        Determine if a process should be blocked from executing commands.
        
        Returns True if taint level exceeds policy threshold.
        """
        max_taint = self.policy.get('max_taint_for_exec', 2)  # Default: MEDIUM
        current_taint = self.get_taint_level(pid)
        
        if current_taint > max_taint:
            log.warning(f"BLOCK: Agent {pid} exceeds taint threshold ({current_taint} > {max_taint})")
            return True
        return False
    
    # === DEBUG ===
    
    def get_state_summary(self) -> dict:
        """Get a summary of current guardian state for debugging."""
        return {
            'agents': {
                pid: {
                    'taint_level': info.taint_level,
                    'active_views': list(info.active_views),
                    'registered_at': info.registered_at
                }
                for pid, info in self.agents.items()
            },
            'active_agent': self.active_agent_pid,
            'taint_records': {
                sid: {
                    'level': rec.level,
                    'url': rec.url,
                    'age_seconds': time.time() - rec.timestamp
                }
                for sid, rec in self.taint_records.items()
            }
        }
