"""
Telos Intent Verifier — Dual-Gate Data Plane Router

Architecture:
    Data Plane (synchronous, deterministic):
        1. Taint check
        2. Domain extraction + Exec action extraction
        3. Domain Intelligence classification (L0-L4) → Network Gate
        4. Execution Intelligence classification (L1-L4) → Exec Gate
        5. Score-based decision: ALLOW / DENY / ESCALATE

    Control Plane (async, rare):
        6. LLM evaluation (only for ESCALATE decisions)
        7. Persist LLM verdict → DB (self-learning)

The LLM is NEVER in the hot path.
Expected LLM call rate: <5% of queries.
"""

import logging
import re
from typing import List, Tuple

from shared import protocol_pb2

log = logging.getLogger('telos.verifier')


class IntentVerifier:
    def __init__(self, guardian):
        self.guardian = guardian

        # --- Data Plane: Domain Intelligence Engine ---
        self.di = None
        try:
            from cortex.domain_intel import DomainIntel
            self.di = DomainIntel()
            stats = self.di.get_stats()
            log.info("Domain Intelligence Engine: %d domains loaded", stats['total'])
        except Exception as e:
            log.warning("Domain Intelligence unavailable: %s", e)

        # --- Control Plane: LLM Verifier (fallback only) ---
        self.llm = None
        try:
            from cortex.llm_verifier import LLMVerifier
            self.llm = LLMVerifier()
            if self.llm.is_available:
                log.info("LLM Verifier: online (control-plane escalation)")
            else:
                self.llm = None
                log.info("LLM Verifier: model not loaded (DI-only mode)")
        except Exception as e:
            log.warning("LLM Verifier unavailable: %s", e)

        # Mode reporting
        if self.di and self.llm:
            log.info("Verifier Mode: FULL (DI + EI + LLM escalation)")
        elif self.di:
            log.info("Verifier Mode: DI-ONLY (deterministic)")
        elif self.llm:
            log.info("Verifier Mode: LLM-ONLY (legacy)")
        else:
            log.warning("Verifier Mode: HEURISTIC FALLBACK")

        # --- Execution Intelligence Engine (Phase 5) ---
        self.ei = None
        try:
            from cortex.exec_intel import ExecIntel
            self.ei = ExecIntel()
            log.info("Execution Intelligence Engine: online")
        except Exception as e:
            log.warning("Execution Intelligence unavailable: %s", e)

    def verify(self, pid: int, goal: str, actions: list, exec_actions: list = None) -> Tuple[bool, str, int, List[str], List[str]]:
        """
        Verify intent. Returns (allowed, reason, ttl_ms, domains, allowed_bins).
        """
        # 1. Taint Check — compromised agents are always denied
        taint = self.guardian.get_taint_level(pid)
        if taint >= protocol_pb2.TaintLevel.HIGH:
            log.warning("Intent Denied: Agent %d is tainted (%d)", pid, taint)
            return False, f"Agent is tainted ({taint}), intent rejected.", 0, [], []

        # 2. Extract domains from network actions
        domains = self._extract_domains(actions)

        # 3. Extract exec actions (Phase 5)
        exec_cmds = self._extract_exec_actions(exec_actions or [])

        # If no actions at all, deny
        if not domains and not exec_cmds:
            log.info("Intent Denied: No network or exec actions found")
            return False, "No verifiable actions detected.", 0, [], []

        # 4. Network Gate: classify domains
        if domains:
            if self.di:
                net_result = self._classify_domains(goal, domains)
            elif self.llm:
                net_result = self._llm_only_verify(goal, domains)
            else:
                net_result = self._heuristic_fallback(goal, domains)

            if not net_result[0]:  # Network gate denied
                return net_result[0], net_result[1], net_result[2], net_result[3], []
        else:
            net_result = (True, "No network actions.", 60000, [])

        allowed_bins = []
        # 5. Execution Gate: classify exec actions (Phase 5)
        if exec_cmds and self.ei:
            exec_result = self._classify_exec_actions(goal, exec_cmds)
            if not exec_result[0]:  # Exec gate denied
                return exec_result[0], exec_result[1], exec_result[2], net_result[3], []
            allowed_bins = exec_result[4]
        elif self.ei:
            # If no explicit exec actions provided, fallback to default safe + intent bins
            intent_bins = list(self.ei._get_allowed_for_intent(goal.lower()))
            safe_padding = [b for b in SAFE_BINARIES if b not in intent_bins]
            allowed_bins = (intent_bins + safe_padding)[:8]

        return net_result[0], net_result[1], net_result[2], net_result[3], allowed_bins

    def _classify_domains(self, goal: str, domains: List[str]) -> Tuple[bool, str, int, List[str]]:
        """
        Data-plane classification via Domain Intelligence Engine.
        LLM called ONLY for ESCALATE decisions (control plane).
        """
        from cortex.domain_intel import ALLOW, DENY, ESCALATE

        verified = []
        denied = []

        for domain in domains:
            decision, score, reason = self.di.classify(domain, goal)

            if decision == ALLOW:
                verified.append(domain)

            elif decision == DENY:
                denied.append((domain, reason, score))

            elif decision == ESCALATE:
                # Control plane: LLM decides
                llm_result = self._escalate_to_llm(goal, domain)
                if llm_result:
                    verified.append(domain)
                else:
                    denied.append((domain, f"LLM denied after escalation", score))

        if denied:
            domain, reason, score = denied[0]
            log.info("[DI] DENIED: %s (score=%d: %s)", domain, score, reason)
            return False, f"Denied: '{domain}' — {reason}", 0, []

        log.info("[DI] VERIFIED: %s → %s", goal, verified)
        return True, "Intent verified by Domain Intelligence.", 60000, verified

    def _escalate_to_llm(self, goal: str, domain: str) -> bool:
        """
        Control-plane escalation: ask LLM for unknown/ambiguous domains.
        Persist verdict for future O(1) lookups (self-learning).
        """
        if not self.llm:
            log.warning("[ESCALATE] No LLM available, denying unknown domain: %s", domain)
            return False

        log.info("[ESCALATE] %s → LLM for domain: %s", goal, domain)
        result = self.llm.verify_action(goal, domain)

        if result is None:
            # LLM inference failed — fail closed
            return False

        allowed, reason = result

        # Self-learning: persist the verdict
        if self.di:
            category = "unknown"
            trust = 50 if allowed else 10
            self.di.persist_verdict(domain, category, trust)

        return allowed

    def _llm_only_verify(self, goal: str, domains: List[str]) -> Tuple[bool, str, int, List[str]]:
        """Legacy path: LLM-only (no DI available)."""
        verified = []
        for domain in domains:
            result = self.llm.verify_action(goal, domain)
            if result and result[0]:
                verified.append(domain)
            else:
                reason = result[1] if result else "LLM denied"
                return False, f"LLM Denied: '{domain}' — {reason}", 0, []
        return True, "Intent verified by LLM.", 60000, verified

    def _heuristic_fallback(self, goal: str, domains: List[str]) -> Tuple[bool, str, int, List[str]]:
        """Last-resort heuristic matching."""
        log.warning("Using heuristic fallback (no DI, no LLM)")
        # Deny by default when no intelligence is available
        return False, "No verification engine available (deny by default).", 0, []

    def _extract_domains(self, actions: list) -> List[str]:
        """Extract domain names from planned network actions."""
        domains = []
        pattern = r'(?:curl|wget|https?://)\s*(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})'
        for action in actions:
            matches = re.findall(pattern, action, re.IGNORECASE)
            domains.extend(matches)
        return list(set(domains))

    def _extract_exec_actions(self, exec_actions: list) -> List[Tuple[str, List[str]]]:
        """
        Extract binary + args from exec actions.
        Format: ['cat /var/log/syslog', 'bash -c rm -rf /tmp']
        Returns: [('cat', ['/var/log/syslog']), ('bash', ['-c', 'rm', '-rf', '/tmp'])]
        """
        import shlex
        results = []
        for action in exec_actions:
            action = action.strip()
            if not action:
                continue
            # Strip 'exec:' prefix if present
            if action.lower().startswith('exec:'):
                action = action[5:].strip()
            try:
                parts = shlex.split(action)
            except ValueError:
                parts = action.split()
            if parts:
                binary = parts[0]
                args = parts[1:] if len(parts) > 1 else []
                results.append((binary, args))
        return results

    def _classify_exec_actions(self, goal: str, exec_cmds: List[Tuple[str, List[str]]]) -> Tuple[bool, str, int, List[str], List[str]]:
        """
        Execution gate: classify each exec action via ExecIntel.
        """
        from cortex.exec_intel import ALLOW, DENY, ESCALATE

        denied = []
        allowed_bins = []
        for binary, args in exec_cmds:
            decision, score, reason, bins = self.ei.classify(binary, args, goal)
            allowed_bins = bins
            if decision == DENY:
                denied.append((binary, reason, score))
            elif decision == ESCALATE:
                log.info("[EI] ESCALATE: %s (score=%d)", binary, score)
                # For now, deny escalated exec actions (fail-closed)
                denied.append((binary, f"Escalated, fail-closed: {reason}", score))

        if denied:
            binary, reason, score = denied[0]
            log.info("[EI] DENIED: %s (score=%d: %s)", binary, score, reason)
            return False, f"Exec denied: '{binary}' — {reason}", 0, [], []

        log.info("[EI] VERIFIED: all exec actions approved for intent: %s", goal)
        return True, "Execution verified.", 60000, [], allowed_bins
