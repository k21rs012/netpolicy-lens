"""Isolate even app.main's import-time store initialization from development DBs."""
import os
import tempfile
from pathlib import Path

_directory = tempfile.TemporaryDirectory(prefix="netpolicy-pytest-")
_previous_database = os.environ.get("DATABASE_PATH")
os.environ["DATABASE_PATH"] = str(Path(_directory.name) / "initial.db")


def pytest_unconfigure(config):
    if _previous_database is None:
        os.environ.pop("DATABASE_PATH", None)
    else:
        os.environ["DATABASE_PATH"] = _previous_database
    _directory.cleanup()
