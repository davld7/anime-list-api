# Anime List API

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.141.1-005571?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-47A248?style=flat&logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![JWT](https://img.shields.io/badge/JWT-HS256-000000?style=flat&logo=jsonwebtokens&logoColor=white)](https://jwt.io/)
[![uv](https://img.shields.io/badge/uv-EBCE4B?style=flat&logo=uv&logoColor=black)](https://docs.astral.sh/uv/)
[![pytest](https://img.shields.io/badge/pytest-9.1.1-0A9EDC?style=flat&logo=pytest&logoColor=white)](https://docs.pytest.org/)
[![Ruff](https://img.shields.io/badge/ruff-0.16.6-00599C?style=flat&logo=ruff&logoColor=white)](https://docs.astral.sh/ruff/)

Modular REST API for managing anime catalogs, built with FastAPI and MongoDB.

## Stack
- Python 3.12
- FastAPI, Pydantic v2, pymongo
- uv (dependency manager)
- JWT HS256 + opaque refresh tokens with atomic rotation

## Environment variables (.env)
```
MONGO_URI="mongodb+srv://..."
DATABASE_NAME="anime_list"
JWT_SECRET_KEY="..."
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=30
```

Use `.env.example` as a template to create your own `.env`.

## Quick Start
```powershell
uv sync
uvicorn main:app --reload
```
- Local Swagger: http://127.0.0.1:8000/docs
- Production Swagger: https://anime-list-api.fastapicloud.dev/docs

## Main endpoints

### Auth (`/auth`)
- `POST /auth/login` — Login, returns access + refresh token
- `POST /auth/refresh` — Refresh token rotation
- `POST /auth/logout` — Revokes refresh token
- `GET /auth/me` — Authenticated user
- `PUT /auth/username` — Change username
- `PUT /auth/password` — Change password
- `GET /auth/users?page=1&active=true` — List users (admin; `page` to paginate, `active` to filter)
- `GET /auth/users/pages` — Total pages of users (admin)
- `GET /auth/users/{id}` — Get user by ID (admin)
- `POST /auth/users` — Create user (admin)
- `PUT /auth/users/{id}/permissions` — Change permissions (admin)
- `PUT /auth/users/{id}/password` — Reset password (admin)
- `PUT /auth/users/{id}/active` — Activate/deactivate user (admin)
- `DELETE /auth/users/{id}` — Delete user (admin)

> Changing `username` or `password` invalidates existing tokens (access and refresh); log in again with the new credentials.

### Animes (`/animes`)
`GET` requests are public (no token required). `POST` and `PUT` require the `write` permission; `DELETE` requires `admin`.
- `GET /` — All animes
- `GET /page` — Paginated
- `GET /pages` — Total pages
- `GET /by-id/{id}` — By ObjectId
- `GET /by-name/{name}` — By name
- `POST /` — Create (`write` permission)
- `PUT /{id}` — Update (`write` permission)
- `DELETE /{id}` — Delete (`admin` permission)

> `/animes/` uses `JSONRepairRoute`: tolerates unescaped newlines in JSON strings.

### Health
- `GET /health` — Checks MongoDB connection

## Permissions
- `read` — Read (animes)
- `write` — Create/update animes
- `admin` — User management and anime deletion

## Admin recovery CLI
```powershell
python -m app.cli.manage_admin status
python -m app.cli.manage_admin create
python -m app.cli.manage_admin reset-password
```

## Development
```powershell
uv sync                # Install/sync dependencies
pytest                 # Tests (use anime_list_test)
ruff check --fix .     # Lint/format
```

## Tests
- `pytest tests/test_auth_*.py` — Auth/permissions
- `pytest tests/test_animes.py` — Anime tests
- `pytest` — Full suite
- Test DB: `anime_list_test` (enforced in `conftest.py`)

## Structure
```
app/
├── routers/      # Endpoints and dependencies
├── repositories/ # Data access
├── db/           # MongoDB and indexes
├── schemas/      # Pydantic models
└── core/         # Config, security, dependencies
```