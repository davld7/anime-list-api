"""Unit tests for the MongoDB connection health check.

These tests are completely isolated from a real MongoDB: the module-level
``client`` read by ``check_database_connection`` is replaced with mocks or
``None`` and restored automatically by monkeypatch.
"""

from unittest.mock import MagicMock

from app.db import database


def test_check_database_connection_returns_false_when_client_is_none(monkeypatch):
    monkeypatch.setattr(database, "client", None)
    assert database.check_database_connection() is False


def test_check_database_connection_returns_true_when_ping_succeeds(monkeypatch):
    mock_client = MagicMock()
    mock_client.admin.command("ping").return_value = {"ok": 1.0}
    monkeypatch.setattr(database, "client", mock_client)
    assert database.check_database_connection() is True


def test_check_database_connection_returns_false_when_ping_fails(monkeypatch):
    mock_client = MagicMock()
    mock_client.admin.command.side_effect = Exception("database unreachable")
    monkeypatch.setattr(database, "client", mock_client)
    assert database.check_database_connection() is False
