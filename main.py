"""Ojas Authentication API.

A small FastAPI service that validates a ``username``/``password`` pair
against ``users.json`` (in this repository) and checks that the matching
account has not expired yet.

Contract
--------
``POST /login`` (also ``GET /login``) with credentials supplied as a JSON
body, form-encoded body, or query parameters:

* Credentials valid **and** current date < expiry  ->  200
      {"status": "Allow", "expiry": "<expiry from users.json>"}
* Anything else                                    ->  401 / 400 / 500
      {"status": "Access Denied", "reason": "<why>"}

Vercel
------
Zero-config deployable: Vercel detects the FastAPI instance named ``app``
in ``main.py`` (with ``fastapi`` listed in ``requirements.txt``) and routes
every request to it, so routes are served at the deployment root, e.g.:

    https://<project>.vercel.app/login
"""

from __future__ import annotations

import hmac
import json
import os
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# --------------------------------------------------------------------------- #
# Locating users.json                                                         #
# --------------------------------------------------------------------------- #

_APP_DIR = Path(__file__).resolve().parent

#: Candidate locations, tried in order (after the USERS_JSON_PATH env var).
_USERS_JSON_CANDIDATES: List[Path] = [
    _APP_DIR / "users.json",  # next to main.py (local + typical Vercel bundle)
    _APP_DIR.parent / "users.json",  # repository root, if bundled in a sub folder
    Path.cwd() / "users.json",  # current working directory
]


def _users_json_path() -> Optional[Path]:
    """Return the first existing users.json location, or None if not found."""
    env_path = os.environ.get("USERS_JSON_PATH", "").strip()
    if env_path:
        candidate = Path(env_path)
        if candidate.is_file():
            return candidate
    for candidate in _USERS_JSON_CANDIDATES:
        if candidate.is_file():
            return candidate
    return None


def _load_users() -> List[Dict[str, Any]]:
    """Read users.json and normalise it into a list of user dictionaries.

    Supported layouts::

        1. single user object : {"username": ..., "password": ..., "expiry": ...}
        2. list of users      : [ {...}, {...} ]
        3. wrapped list       : {"users": [ {...}, {...} ]}
    """
    path = _users_json_path()
    if path is None:
        raise FileNotFoundError("users.json could not be located")
    with path.open("r", encoding="utf-8-sig") as handle:  # utf-8-sig tolerates a BOM
        data = json.load(handle)

    if isinstance(data, list):
        return [user for user in data if isinstance(user, dict)]
    if isinstance(data, dict):
        if isinstance(data.get("users"), list):
            return [user for user in data["users"] if isinstance(user, dict)]
        return [data]
    raise ValueError("users.json must contain an object or a list of objects")


def _find_user(username: str) -> Optional[Dict[str, Any]]:
    """Return the first user whose username matches, using a constant-time compare."""
    username_bytes = username.encode("utf-8")
    for user in _load_users():
        stored = str(user.get("username", ""))
        if hmac.compare_digest(stored.encode("utf-8"), username_bytes):
            return user
    return None


def _parse_expiry(value: Any) -> Optional[date]:
    """Parse an ISO date or ISO datetime string into a date (None if invalid)."""
    if value is None:
        return None
    text = str(value).strip()
    try:
        return date.fromisoformat(text)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text).date()
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Core check                                                                  #
# --------------------------------------------------------------------------- #


def _check_credentials(username: Any, password: Any) -> JSONResponse:
    """Apply the full auth + expiry check and build the API response."""
    if not username or not password:
        return JSONResponse(
            status_code=400,
            content={"status": "Access Denied", "reason": "missing_fields"},
        )

    try:
        user = _find_user(str(username))
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        return JSONResponse(
            status_code=500,
            content={"status": "Access Denied", "reason": f"users.json error: {exc}"},
        )

    if user is None:
        return JSONResponse(
            status_code=401,
            content={"status": "Access Denied", "reason": "invalid_credentials"},
        )

    password_bytes = str(password).encode("utf-8")
    stored_password = str(user.get("password", "")).encode("utf-8")
    if not hmac.compare_digest(stored_password, password_bytes):
        return JSONResponse(
            status_code=401,
            content={"status": "Access Denied", "reason": "invalid_credentials"},
        )

    expiry = _parse_expiry(user.get("expiry"))
    if expiry is None:
        return JSONResponse(
            status_code=500,
            content={"status": "Access Denied", "reason": "invalid_or_missing_expiry"},
        )

    # Spec: allow only while the current date is strictly before the expiry
    # date. Change '<' to '<=' below if the account should stay valid through
    # the expiry day itself.
    if date.today() >= expiry:
        return JSONResponse(
            status_code=401,
            content={"status": "Access Denied", "reason": "expired"},
        )

    return JSONResponse(
        status_code=200,
        content={"status": "Allow", "expiry": str(user.get("expiry"))},
    )


# --------------------------------------------------------------------------- #
# FastAPI app                                                                 #
# --------------------------------------------------------------------------- #

app = FastAPI(
    title="Ojas Authentication API",
    description="Validates username/password against users.json and checks expiry.",
    version="1.0.0",
)

# Permissive CORS so browser-based clients can call the API directly.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", summary="Service info")
async def root() -> Dict[str, Any]:
    """Basic health/service-info endpoint."""
    return {
        "service": "Ojas Authentication API",
        "status": "ok",
        "usage": 'POST /login with JSON body {"username": "...", "password": "..."}',
        "docs": "/docs",
    }


_LOGIN_RESPONSES: Dict[int, Any] = {
    200: {
        "description": "Credentials valid and account not expired.",
        "content": {
            "application/json": {
                "example": {"status": "Allow", "expiry": "2030-12-31"}
            }
        },
    },
    400: {
        "description": "Missing or malformed credentials.",
        "content": {
            "application/json": {
                "example": {"status": "Access Denied", "reason": "missing_fields"}
            }
        },
    },
    401: {
        "description": "Wrong credentials or expired account.",
        "content": {
            "application/json": {
                "example": {"status": "Access Denied", "reason": "expired"}
            }
        },
    },
    500: {
        "description": "users.json missing, unreadable, or has a bad expiry value.",
        "content": {
            "application/json": {
                "example": {
                    "status": "Access Denied",
                    "reason": "invalid_or_missing_expiry",
                }
            }
        },
    },
}


@app.post(
    "/login",
    summary="Check credentials and expiry (JSON or form body)",
    response_description="Allow / Access Denied verdict.",
    responses=_LOGIN_RESPONSES,
    openapi_extra={
        # Declared via openapi_extra (instead of as a typed function
        # parameter) so Swagger UI shows an editable, prefilled JSON body
        # editor while the handler stays flexible enough to also accept
        # form-encoded bodies and query params.
        "requestBody": {
            "required": False,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "username": {"type": "string", "title": "Username"},
                            "password": {"type": "string", "title": "Password"},
                        },
                        "required": ["username", "password"],
                    },
                    "example": {"username": "admin", "password": "admin"},
                }
            },
        }
    },
)
async def login_post(request: Request) -> JSONResponse:
    """Authenticate a user against users.json.

    Credentials are read from a JSON body (preferred) or form-encoded
    fields, with query parameters as a last-resort fallback.
    """
    data: Dict[str, Any] = {}
    content_type = request.headers.get("content-type", "")

    if "application/json" in content_type:
        try:
            parsed = await request.json()
            if isinstance(parsed, dict):
                data = parsed
        except (ValueError, UnicodeDecodeError):
            data = {}
    elif "form" in content_type:
        try:
            form = await request.form()
            data = {key: form[key] for key in form.keys()}
        except Exception:  # malformed or unsupported form encoding
            data = {}

    # Fall back to query parameters when the body did not carry the fields.
    if "username" not in data:
        data["username"] = request.query_params.get("username")
    if "password" not in data:
        data["password"] = request.query_params.get("password")

    return _check_credentials(data.get("username"), data.get("password"))


@app.get(
    "/login",
    summary="Check credentials and expiry (query params)",
    response_description="Allow / Access Denied verdict.",
    responses=_LOGIN_RESPONSES,
)
async def login_get(
    username: Optional[str] = Query(default=None, description="Username to check."),
    password: Optional[str] = Query(default=None, description="Password to check."),
) -> JSONResponse:
    """Authenticate a user against users.json via query parameters.

    Handy for quick browser tests: ``/login?username=admin&password=admin``.
    """
    return _check_credentials(username, password)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))

