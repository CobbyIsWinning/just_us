"""Regression check for message readers coexisting with audit-event writers."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class SQLiteConcurrencyTests(unittest.TestCase):
    def test_audit_write_can_commit_while_a_read_transaction_is_open(self):
        # Import the app's database configuration in isolation so this test
        # never connects to or changes the developer's configured database.
        with tempfile.TemporaryDirectory() as directory:
            environment = {
                **os.environ,
                "DATABASE_URL": f"sqlite:///{directory}/test.db",
            }
            result = subprocess.run(
                [sys.executable, "-c", """
from app.database import engine
with engine.begin() as setup:
    setup.exec_driver_sql('CREATE TABLE events (id INTEGER PRIMARY KEY)')
    setup.exec_driver_sql('INSERT INTO events VALUES (1)')
with engine.connect() as reader:
    reader.exec_driver_sql('BEGIN')
    assert reader.exec_driver_sql('SELECT COUNT(*) FROM events').scalar() == 1
    with engine.connect() as writer:
        writer.exec_driver_sql('PRAGMA busy_timeout=200')
        writer.exec_driver_sql('INSERT INTO events VALUES (2)')
        writer.commit()
    # The reader keeps its original snapshot until its transaction ends.
    assert reader.exec_driver_sql('SELECT COUNT(*) FROM events').scalar() == 1
    reader.rollback()
with engine.connect() as verifier:
    assert verifier.exec_driver_sql('SELECT COUNT(*) FROM events').scalar() == 2

# A no-op legacy backfill must also release its write transaction before
# rendering the room, whose audit events use an independent connection.
from app.database import Base, SessionLocal
from app.models import Room
from app.room_service import backfill_default_room_records
Base.metadata.create_all(engine)
with SessionLocal() as session:
    room = Room(name='General', slug='general', is_default=True)
    session.add(room)
    session.commit()
    backfill_default_room_records(session, room)
    with engine.connect() as audit:
        audit.exec_driver_sql('PRAGMA busy_timeout=200')
        audit.exec_driver_sql('INSERT INTO events VALUES (3)')
        audit.commit()
"""],
                cwd=Path(__file__).resolve().parent,
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
