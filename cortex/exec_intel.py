"""
Telos Execution Intelligence Engine

Deterministic classification of execution actions against intent.
Mirrors the Domain Intelligence Engine architecture.

Pipeline:
    L1 — Safe Binary (O(1) lookup)
    L2 — LOLBin Detection (known-dangerous binaries)
    L3 — Path Traversal / Sensitive Target Check
    L4 — Intent-Binary Mapping (does the binary match the goal?)
    → Combined score → ALLOW / DENY / ESCALATE
"""

import logging
import os
from typing import Optional, Tuple, List, Set

log = logging.getLogger('telos.exec_intel')

# Decision constants
ALLOW    = "ALLOW"
DENY     = "DENY"
ESCALATE = "ESCALATE"

# Score thresholds
BLOCK_THRESHOLD  = 50
REVIEW_THRESHOLD = 30

# Weights
W_LOLBIN           = 70   # Living Off the Land Binary
W_PATH_TRAVERSAL   = 60   # Path traversal attempt
W_SENSITIVE_TARGET = 55   # Accessing sensitive files
W_INTENT_MISMATCH  = 40   # Binary doesn't match intent
W_SAFE_BINARY      = -20  # Trusted read-only tool


# ─── Binary Classification Tables ───────────────────────────

# L1: Universally safe read-only binaries (always allowed)
SAFE_BINARIES = frozenset({
    'cat', 'ls', 'head', 'tail', 'wc', 'grep', 'less', 'more',
    'echo', 'printf', 'date', 'whoami', 'hostname', 'uname',
    'env', 'printenv', 'id', 'pwd', 'basename', 'dirname',
    'sort', 'uniq', 'cut', 'tr', 'tee', 'seq', 'true', 'false',
    'file', 'stat', 'du', 'df', 'free', 'uptime', 'ps',
    'find', 'which', 'type', 'test', '[',
})

# L2: LOLBins — Living Off the Land Binaries
# These are legitimate tools commonly abused for attacks
LOLBINS = frozenset({
    # Shells
    'bash', 'sh', 'zsh', 'dash', 'csh', 'ksh', 'fish',
    # Network exfil
    'nc', 'ncat', 'netcat', 'socat', 'telnet', 'ftp', 'sftp', 'scp',
    'wget', 'curl',  # curl is conditional — might be allowed by intent
    # Privilege escalation / persistence
    'chmod', 'chown', 'chgrp', 'chattr',
    'sudo', 'su', 'doas', 'pkexec',
    # File modification / destruction
    'rm', 'rmdir', 'shred', 'dd', 'mkfs',
    'mv', 'cp',  # conditional
    # Code execution
    'python', 'python3', 'perl', 'ruby', 'node', 'php',
    'gcc', 'g++', 'make', 'cc',
    # Credential access
    'ssh', 'ssh-keygen', 'gpg',
    # System modification
    'mount', 'umount', 'insmod', 'modprobe', 'iptables',
    'systemctl', 'service', 'crontab', 'at',
})

# L3: Sensitive path prefixes
SENSITIVE_PATHS = [
    '/etc/shadow', '/etc/passwd', '/etc/sudoers',
    '/root/', '/home/*/.ssh/', '/home/*/.gnupg/',
    '/var/log/auth', '/proc/kcore', '/dev/mem',
    '/boot/', '/sys/firmware/',
]

# L4: Intent → Allowed Binary Mapping
INTENT_BINARY_MAP = {
    'search':      {'curl', 'wget'},
    'web':         {'curl', 'wget'},
    'download':    {'curl', 'wget', 'pip', 'pip3', 'npm', 'cargo'},
    'read':        {'cat', 'head', 'tail', 'less', 'more', 'grep'},
    'weather':     {'curl'},
    'api':         {'curl'},
    'check':       {'curl', 'ping', 'dig', 'nslookup', 'ss', 'netstat'},
    'server':      {'curl', 'ping'},
    'documentation': {'curl'},
    'install':     {'pip', 'pip3', 'npm', 'cargo', 'apt', 'apt-get'},
    'compile':     {'gcc', 'g++', 'make', 'cc', 'cargo', 'rustc'},
    'build':       {'gcc', 'g++', 'make', 'cc', 'cargo', 'rustc', 'npm'},
    'log':         {'cat', 'tail', 'head', 'grep', 'less', 'journalctl'},
    'file':        {'cat', 'ls', 'head', 'tail', 'stat', 'file'},
    'copy':        {'cp', 'rsync'},
    'move':        {'mv'},
}


class ExecIntel:
    """Deterministic execution action classifier."""

    def classify(self, binary: str, args: List[str], intent: str) -> Tuple[str, int, str, List[str]]:
        """
        Classify an execution action against an intent.

        Args:
            binary: the binary name (e.g., 'bash', 'curl', 'cat')
            args: command arguments
            intent: natural language goal

        Returns:
            (decision, score, reason, allowed_bins)
        """
        binary = os.path.basename(binary).lower().strip()
        intent_lower = intent.lower().strip()
        score = 0
        reasons = []

        # --- L1: Safe Binary Check ---
        if binary in SAFE_BINARIES:
            score += W_SAFE_BINARY
            reasons.append(f"safe binary: {binary}")

        # --- L2: LOLBin Detection ---
        if binary in LOLBINS:
            # Check if intent explicitly allows this LOLBin
            allowed_by_intent = self._intent_allows(binary, intent_lower)
            if not allowed_by_intent:
                score += W_LOLBIN
                reasons.append(f"LOLBin: {binary}")
            else:
                reasons.append(f"LOLBin allowed by intent: {binary}")

        # --- L3: Path Traversal / Sensitive Target ---
        full_cmd = ' '.join([binary] + args)
        if '../' in full_cmd:
            score += W_PATH_TRAVERSAL
            reasons.append("path traversal detected")

        for sensitive in SENSITIVE_PATHS:
            # Simple substring check (good enough for data plane)
            clean_pat = sensitive.rstrip('*').rstrip('/')
            if clean_pat in full_cmd:
                score += W_SENSITIVE_TARGET
                reasons.append(f"sensitive target: {clean_pat}")
                break

        # --- L4: Intent-Binary Mismatch ---
        if binary not in SAFE_BINARIES:
            allowed = self._get_allowed_for_intent(intent_lower)
            if allowed and binary not in allowed:
                score += W_INTENT_MISMATCH
                reasons.append(f"intent mismatch: {binary} not in {allowed}")

        # --- Decision ---
        if score >= BLOCK_THRESHOLD:
            decision = DENY
        elif score >= REVIEW_THRESHOLD:
            decision = ESCALATE
        else:
            decision = ALLOW

        # Compute the set of binaries this intent should allow in BPF
        # Prioritize the explicitly requested binary if allowed, then intent-specific bins, then safe bins
        ordered_bins = [binary] if decision == ALLOW else []
        for b in self._get_allowed_for_intent(intent_lower):
            if b not in ordered_bins:
                ordered_bins.append(b)
        for b in SAFE_BINARIES:
            if b not in ordered_bins:
                ordered_bins.append(b)
            if len(ordered_bins) >= 8:
                break
        
        allowed_bins = ordered_bins[:8]

        reason_str = "; ".join(reasons) if reasons else "clean"
        log.info("[EI] %s %s → %s (score=%d: %s)", binary, args[:2], decision, score, reason_str)

        return decision, score, reason_str, allowed_bins

    def _intent_allows(self, binary: str, intent: str) -> bool:
        """Check if the intent explicitly justifies this LOLBin."""
        for keyword, bins in INTENT_BINARY_MAP.items():
            if keyword in intent and binary in bins:
                return True
        return False

    def _get_allowed_for_intent(self, intent: str) -> Set[str]:
        """Get all binaries allowed by the intent keywords."""
        allowed = set()
        for keyword, bins in INTENT_BINARY_MAP.items():
            if keyword in intent:
                allowed.update(bins)
        return allowed
