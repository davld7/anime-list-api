# AGENTS.md — anime-list-api

## Environment and commands

- **Primary OS**: Windows (PowerShell/Warp).
- **Python**: 3.12 (`.python-version`).
- **Package manager**: `uv` (uses `uv.lock`).
- **Install/sync**: `uv sync` (use `uv sync --refresh` only when a metadata refresh is needed).
- **Run server**: `uvicorn main:app --reload`
- **Tests**: `pytest`
- **Lint/fix**: `ruff check --fix .`
- **Admin recovery CLI**: `python -m app.cli.manage_admin <status|create|reset-password>`
- **Do not use**: `pip`, manual `venv`, or `requirements.txt` as source of truth (legacy reference only).

## Security and configuration (non-negotiable)

1. **Never commit `.env`** — it contains production `MONGO_URI`, `JWT_SECRET_KEY`.
2. **Tests only against `anime_list_test`** — `tests/conftest.py` forces `DATABASE_NAME=anime_list_test` and aborts if it doesn't match. Do not change this.
3. **`JWT_SECRET_KEY` in tests is deterministic** — `conftest.py` sets a test-only secret. Do not override it or introduce real secrets in tests.
4. **`auth_version` is not edited manually** — it is incremented atomically in `update_user_by_id_atomic` to revoke tokens. Modifying it breaks session security.
5. **No destructive operations in production** — tests, scripts, or migrations only against the test DB; production requires explicit authorization.

## Authentication and permissions

- **Access tokens**: JWT HS256 (configurable expiration).
- **Refresh tokens**: opaque, atomic rotation, revocation, TTL in MongoDB.
- **`auth_version`**: part of the session invalidation mechanism. Use `update_user_by_id_atomic` (increments atomically) instead of updating manually.
- **Valid permissions**: `read`, `write`, `admin` (defined in `ALLOWED_PERMISSIONS` in `app/schemas/user.py`).
- **Do not add permissions** without updating the corresponding schema validations and tests.

## Architecture and conventions

```
app/
├── routers/        # Endpoints and dependencies
├── repositories/   # Data access
├── db/             # MongoDB and indexes
├── schemas/        # Pydantic models and validations
└── core/           # Configuration, security, and dependencies
```

- **Routers** (`app/routers/`): endpoints, input validation, auth/permission dependencies.
- **Repositories** (`app/repositories/`): data access logic, atomic operations.
- **Database** (`app/db/`): MongoDB connection, indexes, health check, globals lazy-inited in lifespan.
- **Schemas** (`app/schemas/`): Pydantic v2, `field_validator` for business validations.
- **Config** (`app/core/config.py`): `pydantic-settings`, loads `.env`, `extra="ignore"`.
- **`/animes/` routes** use `JSONRepairRoute` (allows unescaped newlines in JSON strings). Do not remove or change `route_class` without preserving that functionality.

## Tests

- **Understand the type** before modifying: unit tests (mocks) vs integration tests (real MongoDB `anime_list_test`).
- **Respect `anime_list_test`** — the guard in `conftest.py` aborts if `DATABASE_NAME` is not the test DB.
- **Surgical cleanup** — avoid broad `delete_many`/`update_many`; clean only what the test creates.
- **Running after changes**:
  - Auth/permissions: `pytest tests/test_auth_*.py`
  - Animes: `pytest tests/test_animes.py`
  - Full suite: `pytest`
- **Do not ignore failing tests** — investigate the cause before moving on.

## Agent workflow

**Before modifying code**:
1. Inspect the relevant code and understand the context.
2. Identify dependencies and possible side effects.
3. Make the smallest change that solves the task.

**After modifying code**:
1. Run relevant tests.
2. Run `ruff check .`.
3. Review `git diff` and `git status`.
4. Verify there are no changes unrelated to the task.
5. Before finishing a task, verify that `git diff` contains only changes related to the task.

## Git

- **Main branch**: `master`.
- **No automatic commits** — leave changes ready for review.
- **No automatic push** — wait for explicit authorization.
- **Do not discard user changes** without authorization.
- **No destructive operations** (reset, checkout, clean) without authorization.

## Scope and limits

- **Simple, maintainable solutions** — avoid overengineering.
- **No new tools/dependencies/linters/type-checkers** unless the task requires them.
- **Do not modify files unrelated to the task**.
- **Important architectural decisions**: stop and present options before implementing.