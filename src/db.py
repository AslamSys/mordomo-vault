"""
SQLite database layer for mordomo-vault.
Uses plain sqlite3 (built-in). The database file itself is NOT encrypted at the
filesystem level — isolation is provided by the container volume + the fact that
the encrypted_value column stores AES-256-GCM ciphertext (the master key is never
persisted to disk).

Schema:
  secrets   — encrypted secret values
  policies  — per-secret access control rules
  audit_log — immutable access audit trail
"""
import json
import sqlite3
import hashlib
from typing import Optional
from src.config import VAULT_DB_PATH


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(VAULT_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Create tables if they don't exist."""
    conn = _connect()
    with conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS secrets (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                secret_key      TEXT UNIQUE NOT NULL,
                encrypted_value BLOB NOT NULL,
                nonce           BLOB NOT NULL,
                description     TEXT,
                created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS policies (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                secret_key          TEXT NOT NULL REFERENCES secrets(secret_key) ON DELETE CASCADE,
                auth_mode           TEXT NOT NULL CHECK (auth_mode IN ('voice', 'service')),
                allowed_person_ids  TEXT,
                min_confidence      REAL,
                allowed_modules     TEXT NOT NULL,
                module_token_hash   TEXT,
                enabled             INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                secret_key       TEXT NOT NULL,
                requester_module TEXT NOT NULL,
                auth_mode        TEXT NOT NULL,
                person_id        TEXT,
                confidence       REAL,
                granted          INTEGER NOT NULL,
                denial_reason    TEXT,
                timestamp        DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_policies_key ON policies(secret_key);
            CREATE INDEX IF NOT EXISTS idx_audit_key    ON audit_log(secret_key);
            CREATE INDEX IF NOT EXISTS idx_audit_module ON audit_log(requester_module);
        """)
    conn.close()


# ── Secrets ────────────────────────────────────────────────────────────────

def get_secret_raw(secret_key: str) -> Optional[sqlite3.Row]:
    """Return the raw secrets row (nonce + encrypted_value) for decryption."""
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM secrets WHERE secret_key = ?", (secret_key,)
    ).fetchone()
    conn.close()
    return row


def upsert_secret(secret_key: str, nonce: bytes, encrypted_value: bytes, description: str = "") -> None:
    conn = _connect()
    with conn:
        conn.execute("""
            INSERT INTO secrets (secret_key, encrypted_value, nonce, description)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(secret_key) DO UPDATE SET
                encrypted_value = excluded.encrypted_value,
                nonce           = excluded.nonce,
                description     = excluded.description,
                updated_at      = CURRENT_TIMESTAMP
        """, (secret_key, encrypted_value, nonce, description))
    conn.close()


def delete_secret(secret_key: str) -> None:
    conn = _connect()
    with conn:
        conn.execute("DELETE FROM secrets WHERE secret_key = ?", (secret_key,))
    conn.close()


# ── Policies ───────────────────────────────────────────────────────────────

def get_policies(secret_key: str) -> list[sqlite3.Row]:
    conn = _connect()
    rows = conn.execute(
        "SELECT * FROM policies WHERE secret_key = ? AND enabled = 1", (secret_key,)
    ).fetchall()
    conn.close()
    return rows


def upsert_policy(
    secret_key: str,
    auth_mode: str,
    allowed_modules: list[str],
    allowed_person_ids: Optional[list[str]] = None,
    min_confidence: Optional[float] = None,
    module_token: Optional[str] = None,
) -> None:
    token_hash = hashlib.sha256(module_token.encode()).hexdigest() if module_token else None
    conn = _connect()
    with conn:
        conn.execute("""
            INSERT INTO policies
                (secret_key, auth_mode, allowed_person_ids, min_confidence, allowed_modules, module_token_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            secret_key,
            auth_mode,
            json.dumps(allowed_person_ids) if allowed_person_ids else None,
            min_confidence,
            json.dumps(allowed_modules),
            token_hash,
        ))
    conn.close()


def issue_module_token(secret_key: str, module: str, token: str) -> None:
    """Update the module_token_hash for the service policy of a given secret+module."""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = _connect()
    with conn:
        conn.execute("""
            UPDATE policies
            SET module_token_hash = ?
            WHERE secret_key = ? AND auth_mode = 'service'
              AND json_each.value = ?
        """, (token_hash, secret_key, module))
        # Simpler bulk approach — update all service policies for this module
        conn.execute("""
            UPDATE policies
            SET module_token_hash = ?
            WHERE auth_mode = 'service'
              AND instr(allowed_modules, ?) > 0
              AND secret_key IN (SELECT secret_key FROM secrets WHERE secret_key = ?)
        """, (token_hash, module, secret_key))
    conn.close()


def issue_token_for_module(module: str, token: str) -> int:
    """Update token hash on ALL service policies where allowed_modules contains this module."""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = _connect()
    with conn:
        result = conn.execute("""
            UPDATE policies
            SET module_token_hash = ?
            WHERE auth_mode = 'service'
              AND instr(allowed_modules, ?) > 0
        """, (token_hash, module))
        updated = result.rowcount
    conn.close()
    return updated


# ── Audit log ──────────────────────────────────────────────────────────────

def write_audit(
    secret_key: str,
    requester_module: str,
    auth_mode: str,
    granted: bool,
    person_id: Optional[str] = None,
    confidence: Optional[float] = None,
    denial_reason: Optional[str] = None,
) -> None:
    conn = _connect()
    with conn:
        conn.execute("""
            INSERT INTO audit_log
                (secret_key, requester_module, auth_mode, person_id, confidence, granted, denial_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (secret_key, requester_module, auth_mode, person_id, confidence, int(granted), denial_reason))
    conn.close()


def get_all_secrets_raw() -> list[sqlite3.Row]:
    """Return all secrets in their encrypted form."""
    conn = _connect()
    rows = conn.execute("SELECT * FROM secrets").fetchall()
    conn.close()
    return rows
