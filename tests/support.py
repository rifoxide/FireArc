"""Synthetic temporary workspaces for offline unit tests."""

from contextlib import contextmanager
from pathlib import Path
import tempfile


@contextmanager
def temporary():
    approved = Path("/tmp/opencode")
    with tempfile.TemporaryDirectory(prefix="firearc-test-", dir=approved if approved.is_dir() else None) as path:
        yield Path(path)
