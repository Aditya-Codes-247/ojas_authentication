# Ojas Authentication API

A minimal **FastAPI** service, deployable to **Vercel**, that checks a
`username`/`password` pair against `users.json` and reports whether the
account is still valid.

## How it works

For every login request the API:

1. Looks the username up in `users.json`.
2. Verifies the password matches.
3. Compares the current date with the account's `expiry` date.
4. Responds:

| Condition                                        | HTTP | Body                                                        |
| ------------------------------------------------ | ---- | ----------------------------------------------------------- |
| Credentials valid **and** today **<** expiry     | 200  | `{"status": "Allow", "expiry": "<expiry from users.json>"}` |
| Anything else (bad credentials / expired / etc.) | 401  | `{"status": "Access Denied", "reason": "<why>"}`            |

> **Note on the date comparison:** per the spec, access is allowed only while
> the current date is *strictly less than* the expiry date, so on the expiry
> day itself the API already denies access. To keep accounts valid through the
> expiry day, change `<` to `<=` in the comparison inside `main.py`
> (`if date.today() >= expiry:` -> `if date.today() > expiry:`).

## Project structure

```
Ojas_Authentication/
+-- main.py            # FastAPI app (Vercel entrypoint, auto-detected)
+-- users.json         # user credentials + expiry (edit this to manage users)
+-- requirements.txt   # Python dependencies
+-- test_api.py        # test suite (pytest)
+-- .python-version    # pins Python 3.13 (local + Vercel)
+-- .gitignore
+-- README.md
```

## API

### `POST /login`  (also accepts `GET /login?username=...&password=...`)

Credentials can be sent as a **JSON body**, a **form-encoded body**, or
**query parameters**.

```bash
curl -X POST https://<your-project>.vercel.app/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'
```

Allowed response (200):

```json
{"status": "Allow", "expiry": "2030-12-31"}
```

Denied response (401):

```json
{"status": "Access Denied", "reason": "invalid_credentials"}
```

Possible `reason` values: `invalid_credentials`, `expired`,
`missing_fields` (HTTP 400), `invalid_or_missing_expiry` and
`users.json error: ...` (HTTP 500).

### `GET /`

Service info / health check.

Interactive docs are generated automatically at `/docs` and `/redoc`.

## Managing users

`users.json` currently holds a single user object:

```json
{
    "username": "admin",
    "password": "admin",
    "expiry": "2024-12-31"
}
```

The loader also supports a **list** of users (or `{"users": [...]}`), e.g.:

```json
[
    {"username": "admin", "password": "admin", "expiry": "2030-12-31"},
    {"username": "ojas", "password": "s3cret", "expiry": "2027-06-30"}
]
```

`expiry` accepts any ISO date (`2030-12-31`) or ISO datetime
(`2030-12-31T23:59:59`). Dates are compared against the **UTC** date
(serverless runtime clock).

Optionally set the `USERS_JSON_PATH` environment variable (in Vercel project
settings or locally) to point at a users file in another location.

## Run locally

```bash
pip install -r requirements.txt
uvicorn main:app --reload
# or: python main.py
```

Then test:

```bash
curl -X POST http://127.0.0.1:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'
```

Run the test suite:

```bash
pip install pytest httpx
python -m pytest test_api.py -v
```

> With the current `users.json` (`expiry: 2024-12-31`, already in the past),
> `admin`/`admin` correctly returns **Access Denied** with reason `expired`.
> To see the **Allow** path, update the `expiry` value to a future date.

## Test with Swagger UI locally

1. Start the server from the repository root (deps already in
   `requirements.txt`):

   ```bash
   pip install -r requirements.txt
   uvicorn main:app --reload
   # or: python main.py
   ```

2. Open the interactive docs in your browser:

   ```
   http://127.0.0.1:8000/docs        # Swagger UI (try-it-out)
   http://127.0.0.1:8000/redoc       # alternative docs layout
   http://127.0.0.1:8000/openapi.json
   ```

3. In Swagger UI: expand **POST /login** -> **Try it out** -> the JSON body
   is prefilled with `{"username": "admin", "password": "admin"}` -> edit as
   needed -> **Execute** -> the status code and response body appear under
   *Server response*. Alternatively expand **GET /login** and fill the
   `username` / `password` query fields (handy for quick checks).

4. Remember the shipped `users.json` is expired (`2024-12-31`), so
   `admin`/`admin` returns `{"status": "Access Denied", "reason": "expired"}`.
   To see the **Allow** response, set `expiry` to a future date (the file is
   re-read on every request - no restart needed), or start the server with
   `USERS_JSON_PATH` pointing at a separate test file:

   ```powershell
   $env:USERS_JSON_PATH = "C:\path\to\test_users.json"; uvicorn main:app --reload
   ```

The same `/docs` URL works on the deployed app:
`https://<project>.vercel.app/docs`.

## Deploy to Vercel

No `vercel.json` is needed - Vercel auto-detects the FastAPI app (`app`
instance in `main.py` + `fastapi` in `requirements.txt`) and routes every
request to it, so `users.json` sits next to `main.py` and is read at runtime.

**Option A - Vercel CLI**

```bash
npm i -g vercel
vercel           # preview deployment
vercel --prod    # production deployment
```

**Option B - Git integration**

1. Push this repository to GitHub/GitLab/Bitbucket.
2. In the Vercel dashboard: *Add New Project* -> import the repo.
3. Vercel sets Framework Preset to *FastAPI* automatically -> **Deploy**.

Your API will be live at `https://<project>.vercel.app/login`
(`vercel dev` reproduces this locally).

## Security notes

- Passwords are stored and compared in plain text; for anything beyond a
  toy/internal tool consider salted hashes (e.g. bcrypt) and storing users in
  a database or environment-based secret instead of a committed JSON file.
- CORS is currently open (`allow_origins=["*"]`) for easy browser clients -
  tighten it if the API should only be callable from known origins.
