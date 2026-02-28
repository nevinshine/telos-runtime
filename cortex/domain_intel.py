"""
Telos Domain Intelligence Engine

Deterministic, O(1) domain classification for the data plane.
SQLite backend (persistent with WAL, fallback to in-memory).

Pipeline:
    L0 — Root domain extraction (subdomain/combo-squat defense)
    L1 — Exact match (SQLite hash index)
    L2 — Typosquat detection (Levenshtein + homoglyph + embedded brand)
    L3 — Category mismatch scoring (intent → allowed categories)
    L4 — Reputation + risk flag scoring
    → Combined score → ALLOW / DENY / ESCALATE

The LLM is NEVER called from this engine.
LLM escalation is handled by the caller (verifier.py).
"""

import logging
import os
import re
import sqlite3
import time
from typing import Optional, Tuple, Dict, List

log = logging.getLogger('telos.domain_intel')

# Decision constants
ALLOW    = "ALLOW"
DENY     = "DENY"
ESCALATE = "ESCALATE"

# Score thresholds
BLOCK_THRESHOLD  = 60   # score >= this → DENY
REVIEW_THRESHOLD = 30   # score >= this → ESCALATE to LLM
# score < REVIEW → ALLOW

# Weights for scoring components
W_CATEGORY_MISMATCH = 40   # Domain category doesn't match intent
W_LOW_TRUST          = 20   # Trust level below threshold
W_EXFIL_FLAG         = 50   # Known exfil/paste/abuse category
W_TYPOSQUAT          = 70   # Looks like a typosquat of a known domain
W_EMBEDDED_BRAND     = 65   # Known brand embedded in unknown domain (combo-squat)
W_UNKNOWN_DOMAIN     = 25   # Domain not in database at all
W_HIGH_TRUST_BONUS   = -30  # Trusted domain gets a negative (good) score

TRUST_THRESHOLD = 50  # Below this, domain is considered low-trust

# Persistent DB path (fallback to :memory: if not writable)
DB_PATH_DEFAULT = '/var/lib/telos/domain_intel.db'

# Well-known public suffixes (for root domain extraction)
_PUBLIC_SUFFIXES = {
    'com', 'org', 'net', 'io', 'co', 'us', 'uk', 'de', 'fr', 'jp',
    'gov', 'edu', 'mil', 'int', 'eu', 'app', 'dev', 'xyz', 'me',
    'info', 'biz', 'tv', 'cc', 'site', 'online', 'tech', 'nz',
    'co.uk', 'co.jp', 'com.au', 'co.in', 'com.br',
}


def _levenshtein(s1: str, s2: str, max_dist: int = 3) -> int:
    """
    Bounded Levenshtein distance. Returns distance or max_dist+1 if exceeded.
    Pure Python implementation — no external deps.
    """
    len1, len2 = len(s1), len(s2)
    if abs(len1 - len2) > max_dist:
        return max_dist + 1

    # Use two-row approach for memory efficiency
    prev = list(range(len2 + 1))
    curr = [0] * (len2 + 1)

    for i in range(1, len1 + 1):
        curr[0] = i
        row_min = i
        for j in range(1, len2 + 1):
            cost = 0 if s1[i-1] == s2[j-1] else 1
            curr[j] = min(curr[j-1] + 1, prev[j] + 1, prev[j-1] + cost)
            row_min = min(row_min, curr[j])
        if row_min > max_dist:
            return max_dist + 1
        prev, curr = curr, prev

    return prev[len2]


def _normalize_homoglyphs(domain: str) -> str:
    """Normalize homoglyph characters in a domain string."""
    from cortex.domain_data import HOMOGLYPHS
    result = domain
    for fake, real in HOMOGLYPHS.items():
        result = result.replace(fake, real)
    return result


def _extract_root_domain(domain: str) -> str:
    """
    Extract the registrable root domain from a full domain string.
    e.g. 'docs.python.org.malware.net' → 'malware.net'
         'www.google.com' → 'google.com'
         'sub.docs.python.org' → 'python.org'
    """
    parts = domain.lower().strip().rstrip('.').split('.')
    if len(parts) <= 2:
        return '.'.join(parts)

    # Check for compound TLDs (co.uk, com.au, etc.)
    if len(parts) >= 3:
        compound_tld = '.'.join(parts[-2:])
        if compound_tld in _PUBLIC_SUFFIXES:
            return '.'.join(parts[-3:])

    return '.'.join(parts[-2:])


class DomainIntel:
    """
    Deterministic domain classification engine.
    All lookups are O(1) via SQLite indexed hash + bounded string ops.
    Persistent SQLite with WAL for concurrent read/write safety.
    """

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = self._resolve_db_path()
        self.db_path = db_path
        self.conn = None
        self._watchlist = []
        self._intent_categories = {}
        self._init_db()

    @staticmethod
    def _resolve_db_path() -> str:
        """Pick persistent path if writable, else fall back to :memory:."""
        db_dir = os.path.dirname(DB_PATH_DEFAULT)
        try:
            os.makedirs(db_dir, exist_ok=True)
            # Test if we can write
            test_file = os.path.join(db_dir, '.telos_write_test')
            with open(test_file, 'w') as f:
                f.write('ok')
            os.remove(test_file)
            return DB_PATH_DEFAULT
        except (OSError, PermissionError):
            log.warning("Cannot write to %s — using in-memory DB", db_dir)
            return ':memory:'

    def _init_db(self):
        """Initialize SQLite in-memory DB and load seed data."""
        from cortex.domain_data import SEED_DOMAINS, WATCHLIST, INTENT_CATEGORIES

        t0 = time.time()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=OFF")

        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS domains (
                domain   TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                trust    INTEGER NOT NULL DEFAULT 50,
                source   TEXT NOT NULL DEFAULT 'seed'
            )
        """)
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_domain ON domains(domain)")

        # Bulk insert seed data
        self.conn.executemany(
            "INSERT OR IGNORE INTO domains (domain, category, trust) VALUES (?, ?, ?)",
            SEED_DOMAINS
        )
        self.conn.commit()

        self._watchlist = WATCHLIST
        self._intent_categories = INTENT_CATEGORIES

        count = self.conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
        elapsed = (time.time() - t0) * 1000
        log.info("Domain Intelligence DB loaded: %d domains (%.1fms)", count, elapsed)

    def classify(self, domain: str, intent: str) -> Tuple[str, int, str]:
        """
        Classify a domain against an intent.

        Returns:
            (decision, score, reason)
            decision: ALLOW / DENY / ESCALATE
            score: 0-100 risk score
            reason: human-readable explanation
        """
        domain = domain.lower().strip().rstrip('.')
        intent_lower = intent.lower().strip()
        score = 0
        reasons = []

        # --- L0: Root Domain Extraction (combo-squat defense) ---
        root = _extract_root_domain(domain)

        # --- L1: Exact Match ---
        # Try full domain first, then root domain
        row = self.conn.execute(
            "SELECT category, trust FROM domains WHERE domain = ?",
            (domain,)
        ).fetchone()

        # Try www-stripped
        if row is None and domain.startswith("www."):
            row = self.conn.execute(
                "SELECT category, trust FROM domains WHERE domain = ?",
                (domain[4:],)
            ).fetchone()

        # Try root domain match (catches multi-subdomain lookups)
        if row is None and root != domain:
            row = self.conn.execute(
                "SELECT category, trust FROM domains WHERE domain = ?",
                (root,)
            ).fetchone()

        if row:
            category, trust = row

            # --- L3: Category Mismatch ---
            allowed_cats = self._get_allowed_categories(intent_lower)
            if allowed_cats and category not in allowed_cats:
                score += W_CATEGORY_MISMATCH
                reasons.append(f"category mismatch: {category} not in {allowed_cats}")

            # --- L4: Reputation ---
            if category in ("exfil", "paste"):
                score += W_EXFIL_FLAG
                reasons.append(f"exfil/paste risk: {category}")
            elif trust < TRUST_THRESHOLD:
                score += W_LOW_TRUST
                reasons.append(f"low trust: {trust}")
            elif trust >= 70:
                score += W_HIGH_TRUST_BONUS
                reasons.append(f"trusted: {trust}")

        else:
            # Domain not in DB — check root domain first
            score += W_UNKNOWN_DOMAIN
            reasons.append("unknown domain")
            category = "unknown"

        # --- L2: Typosquat + Embedded Brand Detection ---
        typosquat_match = self._check_typosquat(domain)
        if typosquat_match:
            score += W_TYPOSQUAT
            reasons.append(f"typosquat of '{typosquat_match}'")

        # Check for embedded brand in unknown domains (combo-squatting)
        if category == "unknown":
            brand_match = self._check_embedded_brand(domain)
            if brand_match:
                score += W_EMBEDDED_BRAND
                reasons.append(f"embedded brand: '{brand_match}' in domain")

        # --- Decision ---
        if score >= BLOCK_THRESHOLD:
            decision = DENY
        elif score >= REVIEW_THRESHOLD:
            decision = ESCALATE
        else:
            decision = ALLOW

        reason_str = "; ".join(reasons) if reasons else "clean"
        log.info("[DI] %s → %s (score=%d: %s)", domain, decision, score, reason_str)

        return decision, score, reason_str

    def _get_allowed_categories(self, intent: str) -> set:
        """Extract allowed categories from intent keywords."""
        allowed = set()
        for keyword, categories in self._intent_categories.items():
            if keyword in intent:
                allowed.update(categories)
        return allowed

    def _check_typosquat(self, domain: str) -> Optional[str]:
        """
        Check if domain is a typosquat of a watchlist domain.
        Uses bounded Levenshtein + homoglyph normalization.
        Operates on root domain to defeat subdomain-squatting.
        """
        root = _extract_root_domain(domain)
        normalized = _normalize_homoglyphs(root)

        for watched in self._watchlist:
            watched_root = _extract_root_domain(watched)
            # Compare root domains
            dist = _levenshtein(normalized, watched_root, max_dist=2)
            if 0 < dist <= 2:
                return watched

            # Compare base names (without TLD)
            norm_base = normalized.rsplit('.', 1)[0] if '.' in normalized else normalized
            watch_base = watched_root.rsplit('.', 1)[0] if '.' in watched_root else watched_root
            dist_base = _levenshtein(norm_base, watch_base, max_dist=2)
            if 0 < dist_base <= 1:
                return watched

        return None

    def _check_embedded_brand(self, domain: str) -> Optional[str]:
        """
        Detect combo-squatting: a known brand name embedded in an unknown domain.
        e.g., 'docs.python.org.malware.net' → detects 'python.org'
              'google-login.evil.com' → detects 'google'
        """
        domain_lower = domain.lower()
        for watched in self._watchlist:
            # Check if the full watched domain appears as a substring
            if watched in domain_lower and domain_lower != watched:
                return watched
            # Check if the brand name (without TLD) appears
            brand = watched.rsplit('.', 1)[0]
            if len(brand) >= 4 and brand in domain_lower:
                root = _extract_root_domain(domain)
                if root != watched:  # Not the actual domain
                    return watched
        return None

    def persist_verdict(self, domain: str, category: str, trust: int):
        """
        Persist an LLM verdict into the DB for future O(1) lookups.
        This is the self-learning mechanism.
        """
        self.conn.execute(
            "INSERT OR REPLACE INTO domains (domain, category, trust, source) VALUES (?, ?, ?, 'llm')",
            (domain, category, trust)
        )
        self.conn.commit()
        log.info("[DI] Learned: %s → %s (trust=%d)", domain, category, trust)

    def get_stats(self) -> Dict:
        """Return DB statistics."""
        total = self.conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
        by_source = dict(self.conn.execute(
            "SELECT source, COUNT(*) FROM domains GROUP BY source"
        ).fetchall())
        return {"total": total, "by_source": by_source}
