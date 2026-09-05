# Anime List API

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.141.0-005571?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-47A248?style=flat&logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![JWT](https://img.shields.io/badge/JWT-HS256-000000?style=flat&logo=jsonwebtokens&logoColor=white)](https://jwt.io/)
[![uv](https://img.shields.io/badge/uv-0.5.0-EBCE4B?style=flat&logo=uv&logoColor=black)](https://docs.astral.sh/uv/)
[![pytest](https://img.shields.io/badge/pytest-9.1.1-0A9EDC?style=flat&logo=pytest&logoColor=white)](https://docs.pytest.org/)
[![Ruff](https://img.shields.io/badge/ruff-0.16.4-00599C?style=flat&logo=ruff&logoColor=white)](https://docs.astral.sh/ruff/)

REST API modular para gestión de catálogos de anime, construida con FastAPI y MongoDB.

## Stack
- Python 3.12
- FastAPI, Pydantic v2, pymongo
- uv (gestor de dependencias)
- JWT HS256 + refresh tokens opacos con rotación atómica

## Variables de entorno (.env)
```
MONGO_URI="mongodb+srv://..."
DATABASE_NAME="anime_list"
JWT_SECRET_KEY="..."
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=30
```

Usa `.env.example` como plantilla para crear tu propio `.env`.

## Quick Start
```powershell
uv sync
uvicorn main:app --reload
```
- Swagger local: http://127.0.0.1:8000/docs
- Swagger producción: https://anime-list-api.fastapicloud.dev/docs

## Endpoints principales

### Auth (`/auth`)
- `POST /login` — Login, devuelve access + refresh token
- `POST /refresh` — Rotación de refresh token
- `POST /logout` — Revoca refresh token
- `GET /me` — Usuario autenticado
- `PUT /username` — Cambiar username (incrementa auth_version)
- `PUT /password` — Cambiar password (incrementa auth_version)
- `GET /users` — Listar usuarios (admin)
- `POST /users` — Crear usuario (admin)
- `PUT /users/{id}/permissions` — Cambiar permisos (admin)
- `PUT /users/{id}/password` — Reset password admin (admin)
- `PUT /users/{id}/active` — Activar/desactivar usuario (admin)
- `DELETE /users/{id}` — Eliminar usuario (admin)

### Animes (`/animes`) — requiere permiso `write` (crear/actualizar) o `admin` (eliminar)
- `GET /` — Todos los animes
- `GET /page` — Paginado
- `GET /pages` — Total páginas
- `GET /by-id/{id}` — Por ObjectId
- `GET /by-name/{name}` — Por nombre
- `POST /` — Crear (permiso `write`)
- `PUT /{id}` — Actualizar (permiso `write`)
- `DELETE /{id}` — Eliminar (permiso `admin`)

> `/animes/` usa `JSONRepairRoute`: tolera newlines sin escapar en strings JSON.

### Health
- `GET /health` — Verifica conexión a MongoDB

## Permisos
- `read` — Lectura (animes)
- `write` — Crear/actualizar animes
- `admin` — Gestión de usuarios y eliminación de animes

## CLI de recuperación de admin
```powershell
python -m app.cli.manage_admin status
python -m app.cli.manage_admin create
python -m app.cli.manage_admin reset-password
```

## Desarrollo
```powershell
uv sync                # Instalar/sincronizar dependencias
pytest                 # Tests (usan anime_list_test)
ruff check --fix .     # Lint/format
```

## Tests
- `pytest tests/test_auth_*.py` — Auth/permisos
- `pytest tests/test_animes.py` — Tests de animes
- `pytest` — Suite completa
- BD de test: `anime_list_test` (forzado en `conftest.py`)

## Estructura
```
app/
├── routers/      # Endpoints y dependencias
├── repositories/ # Acceso a datos
├── db/           # MongoDB e índices
├── schemas/      # Modelos Pydantic
└── core/         # Config, seguridad, dependencias
```
