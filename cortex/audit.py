import sqlite3
import os
import time
from typing import Optional
from cortex.logger import get_logger

log = get_logger("telos.audit")

class AuditTrail:
    """
    Persistent SQLite audit trail for forensic compliance and SIEM ingestion.
    Records taint state changes and execution events.
    """
    
    def __init__(self, db_path: str = "/var/log/telos/audit.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path) or '.', exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize SQLite database with WAL mode."""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS taint_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                pid INTEGER NOT NULL,
                old_taint INTEGER NOT NULL,
                new_taint INTEGER NOT NULL,
                source TEXT NOT NULL,
                reason TEXT
            );
            
            CREATE TABLE IF NOT EXISTS exec_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                pid INTEGER NOT NULL,
                binary TEXT NOT NULL,
                action TEXT NOT NULL,
                taint_level INTEGER NOT NULL
            );
            
            CREATE TABLE IF NOT EXISTS intent_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                agent_name TEXT NOT NULL,
                intent_type TEXT NOT NULL,
                target TEXT NOT NULL,
                ttl_ms INTEGER NOT NULL
            );
        """)
        self.conn.commit()
        log.info("SQLite audit trail initialized", path=self.db_path)

    def log_taint(self, pid: int, old_taint: int, new_taint: int, source: str, reason: str = ""):
        """Log a taint level change."""
        try:
            self.conn.execute(
                "INSERT INTO taint_events (timestamp, pid, old_taint, new_taint, source, reason) VALUES (?, ?, ?, ?, ?, ?)",
                (time.time(), pid, old_taint, new_taint, source, reason)
            )
            self.conn.commit()
        except Exception as e:
            log.error("Failed to log taint event", error=str(e))

    def log_exec(self, pid: int, binary: str, action: str, taint_level: int):
        """Log an execution intent event (e.g. ALLOW/DENY)."""
        try:
            self.conn.execute(
                "INSERT INTO exec_events (timestamp, pid, binary, action, taint_level) VALUES (?, ?, ?, ?, ?)",
                (time.time(), pid, binary, action, taint_level)
            )
            self.conn.commit()
        except Exception as e:
            log.error("Failed to log exec event", error=str(e))
            
    def log_intent(self, agent_name: str, intent_type: str, target: str, ttl_ms: int):
        """Log an explicit intent declaration."""
        try:
            self.conn.execute(
                "INSERT INTO intent_events (timestamp, agent_name, intent_type, target, ttl_ms) VALUES (?, ?, ?, ?, ?)",
                (time.time(), agent_name, intent_type, target, ttl_ms)
            )
            self.conn.commit()
        except Exception as e:
            log.error("Failed to log intent event", error=str(e))
