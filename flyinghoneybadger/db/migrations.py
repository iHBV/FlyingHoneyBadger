"""Simple schema migration support for FlyingHoneyBadger databases.

Tracks schema version in a metadata table and applies migrations sequentially.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.orm import Session

from flyinghoneybadger.utils.logger import get_logger

log = get_logger("migrations")

CURRENT_VERSION = 1

MIGRATIONS: dict[int, list[str]] = {
    # Version 1: Initial schema (created by schema.py Base.metadata.create_all)
    1: [],
}


def get_schema_version(db: Session) -> int:
    """Get the current schema version from the database."""
    try:
        result = db.execute(text("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1"))
        row = result.fetchone()
        return row[0] if row else 0
    except Exception:
        return 0


def ensure_version_table(db: Session) -> None:
    """Create the schema_version table if it doesn't exist."""
    db.execute(text("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))
    db.commit()


def migrate(db: Session) -> None:
    """Apply any pending migrations."""
    ensure_version_table(db)
    current = get_schema_version(db)

    if current >= CURRENT_VERSION:
        return

    for version in range(current + 1, CURRENT_VERSION + 1):
        statements = MIGRATIONS.get(version, [])
        for stmt in statements:
            db.execute(text(stmt))
        db.execute(
            text("INSERT INTO schema_version (version) VALUES (:v)"),
            {"v": version},
        )
        db.commit()
        log.info("Applied migration to version %d", version)
