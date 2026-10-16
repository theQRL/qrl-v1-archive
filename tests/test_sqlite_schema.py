"""The published SQLite v1 DDL must retain its version and required tables."""

import sqlite3
from pathlib import Path


def test_sqlite_v1_schema_contract():
    schema = Path(__file__).parents[1] / "schemas" / "qrl-v1-sqlite-v1.sql"
    packaged = Path(__file__).parents[1] / "src" / "qrl_archive" / "qrl-v1-sqlite-v1.sql"
    assert schema.read_bytes() == packaged.read_bytes()
    with sqlite3.connect(":memory:") as database:
        database.executescript(schema.read_text("utf-8"))
        assert database.execute("PRAGMA application_id").fetchone() == (0x51524C31,)
        assert database.execute("PRAGMA user_version").fetchone() == (1,)
        assert database.execute("PRAGMA foreign_keys").fetchone() == (1,)
        tables = {row[0] for row in database.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )}
        assert tables == {
            "archive_meta", "blocks", "transactions", "tx_outputs",
            "address_events", "final_address_state", "tx_details",
            "genesis_allocations",
        }
        strict_tables = {row[1] for row in database.execute("PRAGMA table_list") if row[5] == 1}
        assert strict_tables == tables
        indexes = {row[0] for row in database.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL"
        )}
        assert indexes == {
            "transactions_height", "transactions_from", "transactions_signer",
            "outputs_to", "address_events_page",
        }
