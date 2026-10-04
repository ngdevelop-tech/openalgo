"""Regression tests for session expiry side effects."""

import os
import sys

import pytest
from flask import Flask, session

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database.auth_db as auth_db  # noqa: E402
import extensions  # noqa: E402
import utils.session as session_utils  # noqa: E402


def test_auto_expiry_broadcasts_force_logout_to_all_devices(monkeypatch):
    """3 AM auto-expiry should notify other browser sessions immediately."""
    app = Flask(__name__)
    app.secret_key = "test-secret"
    emitted = []

    class FakeSocketIO:
        def emit(self, event, payload):
            emitted.append((event, payload))

    monkeypatch.setattr(auth_db, "upsert_auth", lambda *args, **kwargs: 1)
    monkeypatch.setattr(auth_db, "clear_user_sessions", lambda username: None)
    monkeypatch.setattr(extensions, "socketio", FakeSocketIO())
    monkeypatch.setattr(
        "database.cache_invalidation.publish_all_cache_invalidation",
        lambda username: None,
    )
    monkeypatch.setattr("database.master_contract_cache_hook.clear_cache_on_logout", lambda: None)
    monkeypatch.setattr("database.settings_db.clear_settings_cache", lambda: None)
    monkeypatch.setattr("database.telegram_db.clear_telegram_cache", lambda: None)

    with app.test_request_context("/"):
        session["user"] = "rajandran"
        session_utils.revoke_user_tokens(revoke_db_tokens=True)

    assert ("active_sessions_update", {"count": 0, "sessions": []}) in emitted
    force_logout_events = [payload for event, payload in emitted if event == "force_logout"]
    assert force_logout_events
    assert "Session expired" in force_logout_events[0]["message"]


def _patch_revoke_side_effects(monkeypatch, revoke_calls):
    monkeypatch.setattr(
        auth_db, "upsert_auth", lambda *args, **kwargs: revoke_calls.append(args) or 1
    )
    monkeypatch.setattr(auth_db, "clear_user_sessions", lambda username: None)
    monkeypatch.setattr(extensions, "socketio", type("FakeSocketIO", (), {"emit": lambda self, *a, **k: None})())
    monkeypatch.setattr(
        "database.cache_invalidation.publish_all_cache_invalidation",
        lambda username: None,
    )
    monkeypatch.setattr("database.master_contract_cache_hook.clear_cache_on_logout", lambda: None)
    monkeypatch.setattr("database.settings_db.clear_settings_cache", lambda: None)
    monkeypatch.setattr("database.telegram_db.clear_telegram_cache", lambda: None)


def _make_test_app():
    app = Flask(__name__)
    app.secret_key = "test-secret"

    @app.route("/auth/login", endpoint="auth.login")
    def login():
        return "login page"

    @app.route("/protected")
    @session_utils.check_session_validity
    def protected():
        return "ok"

    return app


def test_check_session_validity_skips_db_revoke_mid_broker_connect(monkeypatch):
    """Regression for the OpenAlgo login-loop RCA (2026-08-22): a session that
    completed password login but never finished broker OAuth (``logged_in``
    never set) must not have its DB broker token revoked just because a
    ``@check_session_validity`` route is hit while it's technically invalid.

    Before this fix, hitting ANY of the ~300 decorated routes in this state
    called ``revoke_user_tokens()`` unconditionally, discarding a broker token
    injected out-of-band (e.g. NQE pushing a fresh Kite token) moments
    earlier — the user never left the "connect your broker" loop even after a
    fresh Kite relogin, no matter how many times it was retried.
    """
    app = _make_test_app()
    revoke_calls = []
    monkeypatch.setattr(auth_db, "upsert_auth", lambda *args, **kwargs: revoke_calls.append(args) or 1)

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user"] = "rajandran"
            # logged_in intentionally left unset — mid broker-connect

        resp = client.get("/protected")

    assert resp.status_code == 302
    assert revoke_calls == []


def test_check_session_validity_still_revokes_a_genuinely_expired_session(monkeypatch):
    """A session that WAS fully broker-authenticated and has now genuinely
    expired (past SESSION_EXPIRY_TIME) must still revoke the DB broker token —
    preserving the fix for #1419 (a stale, broker-side-invalidated token being
    silently resumed instead of forcing fresh broker auth).
    """
    app = _make_test_app()
    revoke_calls = []
    _patch_revoke_side_effects(monkeypatch, revoke_calls)

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user"] = "rajandran"
            sess["logged_in"] = True
            sess["broker"] = "zerodha"
            sess["login_time"] = "2020-01-01T00:00:00+05:30"  # long past today's expiry

        resp = client.get("/protected")

    assert resp.status_code == 302
    assert len(revoke_calls) == 1
