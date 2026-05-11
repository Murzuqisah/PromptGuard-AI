"""SQLite-backed policy store.

Persists rule enabled/disabled state and custom rules.
On first run, seeds the database with all built-in rules from rules.py.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from .config import DATABASE_PATH
from .rules import PROMPT_RULES, SECRET_RULES, TOOL_RULES, Rule

_ALL_BUILTIN_RULES = [*PROMPT_RULES, *SECRET_RULES, *TOOL_RULES]


def _get_conn() -> sqlite3.Connection:
    Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    """Create tables and seed built-in rules if not present."""
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS policies (
            rule_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            severity INTEGER NOT NULL,
            decision TEXT NOT NULL,
            explanation TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            is_builtin INTEGER NOT NULL DEFAULT 1,
            pattern TEXT DEFAULT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # Seed built-in rules
    for rule in _ALL_BUILTIN_RULES:
        conn.execute("""
            INSERT OR IGNORE INTO policies (rule_id, name, category, severity, decision, explanation, enabled, is_builtin, pattern)
            VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?)
        """, (rule.rule_id, rule.name, rule.category, rule.severity, rule.decision.value, rule.explanation, rule.pattern.pattern))

    conn.commit()
    conn.close()


def get_all_policies() -> list[dict[str, Any]]:
    conn = _get_conn()
    rows = conn.execute("SELECT * FROM policies ORDER BY category, rule_id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_policy(rule_id: str) -> dict[str, Any] | None:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM policies WHERE rule_id = ?", (rule_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_policy(rule_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
    conn = _get_conn()
    allowed_fields = {"enabled", "name", "severity", "decision", "explanation"}
    fields = {k: v for k, v in updates.items() if k in allowed_fields}
    if not fields:
        conn.close()
        return get_policy(rule_id)

    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [rule_id]
    conn.execute(f"UPDATE policies SET {set_clause} WHERE rule_id = ?", values)
    conn.commit()
    conn.close()
    return get_policy(rule_id)


def create_policy(data: dict[str, Any]) -> dict[str, Any]:
    conn = _get_conn()
    conn.execute("""
        INSERT INTO policies (rule_id, name, category, severity, decision, explanation, enabled, is_builtin, pattern)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
    """, (
        data["rule_id"], data["name"], data["category"],
        data["severity"], data["decision"], data["explanation"],
        1 if data.get("enabled", True) else 0,
        data.get("pattern", ""),
    ))
    conn.commit()
    conn.close()
    return get_policy(data["rule_id"])  # type: ignore


def delete_policy(rule_id: str) -> bool:
    conn = _get_conn()
    # Only allow deleting custom (non-builtin) rules
    result = conn.execute("DELETE FROM policies WHERE rule_id = ? AND is_builtin = 0", (rule_id,))
    conn.commit()
    conn.close()
    return result.rowcount > 0


def get_disabled_rule_ids() -> set[str]:
    """Return set of rule_ids that are disabled."""
    conn = _get_conn()
    rows = conn.execute("SELECT rule_id FROM policies WHERE enabled = 0").fetchall()
    conn.close()
    return {r["rule_id"] for r in rows}


# Initialize on import
init_db()
