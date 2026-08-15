"""SQLite-backed OMEMO storage for the Hermes XMPP adapter.

Implements the ``omemo.storage.Storage`` abstract class using aiosqlite so
all DB I/O stays on the adapter's async event loop.  The database file lives
at ``XMPP_OMEMO_STORE_DIR / omemo.db`` (default:
``~/.hermes/platforms/xmpp/store/omemo.db``).

The store is durable — the plan document is explicit that wiping it rotates
the bot's device identity and forces every peer to re-trust.  The only
supported "reset" path is ``rm`` on the whole store directory, which is
equivalent to starting fresh.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import aiosqlite
from omemo.storage import Just, Maybe, Nothing, Storage
from omemo.types import JSONType

logger = logging.getLogger(__name__)

_DEFAULT_STORE_DIR = os.path.join(
    os.environ.get("HERMES_HOME", os.path.expanduser("~/.hermes")),
    "platforms",
    "xmpp",
    "store",
)

_DB_FILENAME = "omemo.db"

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS omemo_store (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
)
"""


class HermesOMEMOStorage(Storage):
    """Async SQLite storage backend for OMEMO session state.

    Uses a single key-value table with JSON-serialised values, matching the
    simple ``Storage`` interface.  Writes are committed immediately (no
    deferred caching) because the base class already provides an in-memory
    caching layer.
    """

    def __init__(self, db_path: str | Path | None = None) -> None:
        super().__init__(disable_cache=False)
        if db_path is None:
            store_dir = os.environ.get("XMPP_OMEMO_STORE_DIR", _DEFAULT_STORE_DIR)
            os.makedirs(store_dir, exist_ok=True)
            db_path = os.path.join(store_dir, _DB_FILENAME)
        self._db_path = str(db_path)
        self._db: aiosqlite.Connection | None = None

    async def _get_db(self) -> aiosqlite.Connection:
        if self._db is None:
            self._db = await aiosqlite.connect(self._db_path)
            self._db.row_factory = aiosqlite.Row
            await self._db.execute(_CREATE_TABLE_SQL)
            await self._db.commit()
        return self._db

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    # --- Storage interface ---------------------------------------------------

    async def _load(self, key: str) -> Maybe[JSONType]:
        db = await self._get_db()
        async with db.execute(
            "SELECT value FROM omemo_store WHERE key = ?", (key,)
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return Nothing()
        return Just(json.loads(row["value"]))

    async def _store(self, key: str, value: JSONType) -> None:
        db = await self._get_db()
        await db.execute(
            "INSERT OR REPLACE INTO omemo_store (key, value) VALUES (?, ?)",
            (key, json.dumps(value, separators=(",", ":"))),
        )
        await db.commit()

    async def _delete(self, key: str) -> None:
        db = await self._get_db()
        await db.execute("DELETE FROM omemo_store WHERE key = ?", (key,))
        await db.commit()