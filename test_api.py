"""Tests for the Ojas Authentication API (main.py).

Run with::

    python -m pytest test_api.py -v
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import main

FUTURE = (date.today() + timedelta(days=365)).isoformat()
PAST = (date.today() - timedelta(days=1)).isoformat()
TODAY = date.today().isoformat()


@pytest.fixture
def client_factory(tmp_path, monkeypatch):
    """Factory that spins the app up against a temporary users.json file."""

    def _factory(users=None, raw=None):
        path = tmp_path / "users.json"
        path.write_text(
            raw if raw is not None else json.dumps(users), encoding="utf-8"
        )
        monkeypatch.setenv("USERS_JSON_PATH", str(path))
        return TestClient(main.app)

    return _factory


# --------------------------------------------------------------------------- #
# Allow cases                                                                 #
# --------------------------------------------------------------------------- #


def test_allow_valid_credentials_json_body(client_factory):
    client = client_factory(
        [{"username": "admin", "password": "s3cret", "expiry": FUTURE}]
    )
    response = client.post(
        "/login", json={"username": "admin", "password": "s3cret"}
    )
    assert response.status_code == 200
    assert response.json() == {"status": "Allow", "expiry": FUTURE}


def test_allow_single_object_layout(client_factory):
    """users.json holding a single object (the repo's current layout)."""
    client = client_factory(
        raw=json.dumps(
            {"username": "admin", "password": "admin", "expiry": FUTURE}
        )
    )
    response = client.post("/login", json={"username": "admin", "password": "admin"})
    assert response.status_code == 200
    assert response.json() == {"status": "Allow", "expiry": FUTURE}


def test_allow_users_json_with_utf8_bom(client_factory):
    """Windows editors often save JSON with a UTF-8 BOM; it must still parse."""
    client = client_factory(
        raw="\ufeff"
        + json.dumps(
            {"username": "admin", "password": "admin", "expiry": FUTURE}
        )
    )
    response = client.post("/login", json={"username": "admin", "password": "admin"})
    assert response.status_code == 200
    assert response.json()["status"] == "Allow"


def test_allow_wrapped_users_list_layout(client_factory):
    client = client_factory(
        {"users": [{"username": "u1", "password": "p1", "expiry": FUTURE}]}
    )
    response = client.post("/login", json={"username": "u1", "password": "p1"})
    assert response.status_code == 200
    assert response.json()["status"] == "Allow"


def test_allow_via_query_params(client_factory):
    client = client_factory(
        [{"username": "admin", "password": "admin", "expiry": FUTURE}]
    )
    response = client.get("/login?username=admin&password=admin")
    assert response.status_code == 200
    assert response.json()["status"] == "Allow"


def test_allow_via_form_encoded_body(client_factory):
    client = client_factory(
        [{"username": "admin", "password": "admin", "expiry": FUTURE}]
    )
    response = client.post("/login", data={"username": "admin", "password": "admin"})
    assert response.status_code == 200
    assert response.json()["status"] == "Allow"


# --------------------------------------------------------------------------- #
# Access Denied cases                                                         #
# --------------------------------------------------------------------------- #


def test_denied_wrong_password(client_factory):
    client = client_factory(
        [{"username": "admin", "password": "s3cret", "expiry": FUTURE}]
    )
    response = client.post("/login", json={"username": "admin", "password": "wrong"})
    assert response.status_code == 401
    assert response.json()["status"] == "Access Denied"


def test_denied_unknown_username(client_factory):
    client = client_factory(
        [{"username": "admin", "password": "admin", "expiry": FUTURE}]
    )
    response = client.post("/login", json={"username": "ghost", "password": "admin"})
    assert response.status_code == 401
    assert response.json()["status"] == "Access Denied"


def test_denied_when_expired(client_factory):
    client = client_factory(
        [{"username": "admin", "password": "admin", "expiry": PAST}]
    )
    response = client.post("/login", json={"username": "admin", "password": "admin"})
    assert response.status_code == 401
    body = response.json()
    assert body["status"] == "Access Denied"
    assert body["reason"] == "expired"


def test_denied_on_expiry_day_strict_comparison(client_factory):
    """Spec: current date must be strictly less than the expiry date."""
    client = client_factory(
        [{"username": "admin", "password": "admin", "expiry": TODAY}]
    )
    response = client.post("/login", json={"username": "admin", "password": "admin"})
    assert response.status_code == 401
    assert response.json()["status"] == "Access Denied"


def test_denied_missing_fields(client_factory):
    client = client_factory(
        [{"username": "admin", "password": "admin", "expiry": FUTURE}]
    )
    response = client.post("/login", json={"username": "admin"})
    assert response.status_code == 400
    assert response.json()["status"] == "Access Denied"


def test_denied_invalid_json_body_and_no_query_params(client_factory):
    client = client_factory(
        [{"username": "admin", "password": "admin", "expiry": FUTURE}]
    )
    response = client.post(
        "/login", content=b"{not json", headers={"content-type": "application/json"}
    )
    assert response.status_code == 400
    assert response.json()["status"] == "Access Denied"


def test_denied_invalid_expiry_value(client_factory):
    client = client_factory(
        [{"username": "admin", "password": "admin", "expiry": "not-a-date"}]
    )
    response = client.post("/login", json={"username": "admin", "password": "admin"})
    assert response.status_code == 500
    assert response.json()["reason"] == "invalid_or_missing_expiry"


def test_error_when_users_json_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("USERS_JSON_PATH", str(tmp_path / "nope.json"))
    monkeypatch.setattr(main, "_USERS_JSON_CANDIDATES", [tmp_path / "nope.json"])
    client = TestClient(main.app)
    response = client.post("/login", json={"username": "admin", "password": "admin"})
    assert response.status_code == 500
    assert response.json()["status"] == "Access Denied"


def test_error_when_users_json_is_invalid_json(client_factory):
    client = client_factory(raw="{ this is not json")
    response = client.post("/login", json={"username": "admin", "password": "admin"})
    assert response.status_code == 500
    assert "users.json error" in response.json()["reason"]


# --------------------------------------------------------------------------- #
# Other endpoints / the real users.json                                       #
# --------------------------------------------------------------------------- #


def test_root_endpoint_returns_service_info():
    client = TestClient(main.app)
    response = client.get("/")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "Ojas Authentication API"


def test_against_real_repo_users_json(monkeypatch):
    """The actual users.json ships admin/admin expired 2024-12-31 -> Access Denied."""
    monkeypatch.delenv("USERS_JSON_PATH", raising=False)
    client = TestClient(main.app)
    response = client.post("/login", json={"username": "admin", "password": "admin"})
    assert response.status_code == 401
    body = response.json()
    assert body["status"] == "Access Denied"
    assert body["reason"] == "expired"

