# AGENTS.md — anime-list-api

## Entorno y comandos

- **SO principal**: Windows (PowerShell/Warp).
- **Python**: 3.12 (`.python-version`).
- **Gestor**: `uv` (existe `uv.lock`).
- **Instalar/sincronizar**: `uv sync` (usa `uv sync --refresh` solo cuando sea necesario refrescar metadatos).
- **Ejecutar servidor**: `uvicorn main:app --reload`
- **Tests**: `pytest`
- **Lint/fix**: `ruff check --fix .`
- **CLI de recuperación de admin**: `python -m app.cli.manage_admin <status|create|reset-password>`
- **No usar**: `pip`, `venv` manual, `requirements.txt` como fuente de verdad (solo referencia legacy).

## Seguridad y configuración (no negociables)

1. **Nunca commitear `.env`** — contiene `MONGO_URI`, `JWT_SECRET_KEY` de producción.
2. **Tests solo contra `anime_list_test`** — `tests/conftest.py` fuerza `DATABASE_NAME=anime_list_test` y aborta si no coincide. No cambies esto.
3. **`JWT_SECRET_KEY` en tests es determinístico** — `conftest.py` establece un secreto exclusivo para pruebas. No lo sobrescribas ni introduzcas secretos reales en los tests.
4. **`auth_version` no se edita a mano** — se incrementa atómicamente en `update_user_by_id_atomic` para revocar tokens. Modificarlo rompe seguridad de sesiones.
5. **No operaciones destructivas en producción** — tests, scripts o migraciones solo contra BD de test; producción requiere autorización explícita.

## Autenticación y permisos

- **Access tokens**: JWT HS256 (expiración configurable).
- **Refresh tokens**: opacos, rotación atómica, revocación, TTL en MongoDB.
- **`auth_version`**: parte del mecanismo de invalidación de sesiones. Usa `update_user_by_id_atomic` (incrementa atómicamente) en lugar de actualizar manualmente.
- **Permisos válidos**: `read`, `write`, `admin` (definidos en `ALLOWED_PERMISSIONS` en `app/schemas/user.py`).
- **No añadas permisos** sin actualizar validaciones en schemas y tests correspondientes.

## Arquitectura y convenciones

```
app/
├── routers/        # Endpoints y dependencias
├── repositories/   # Acceso a datos
├── db/             # MongoDB e índices
├── schemas/        # Modelos y validaciones Pydantic
└── core/           # Configuración, seguridad y dependencias
```

- **Routers** (`app/routers/`): endpoints, validación de entrada, dependencias de auth/permisos.
- **Repositories** (`app/repositories/`): lógica de acceso a datos, operaciones atómicas.
- **Database** (`app/db/`): conexión MongoDB, índices, health check, globals lazy-inited en lifespan.
- **Schemas** (`app/schemas/`): Pydantic v2, `field_validator` para validaciones de negocio.
- **Config** (`app/core/config.py`): `pydantic-settings`, carga `.env`, `extra="ignore"`.
- **Rutas `/animes/`** usan `JSONRepairRoute` (permite newlines sin escapar en strings JSON). No elimines ni cambies `route_class` sin preservar esa funcionalidad.

## Tests

- **Entiende el tipo** antes de modificar: unitarios (mocks) vs integración (MongoDB real `anime_list_test`).
- **Respetan `anime_list_test`** — el guard en `conftest.py` aborta si `DATABASE_NAME` no es test.
- **Limpieza quirúrgica** — evita `delete_many`/`update_many` amplios; limpia solo lo que el test crea.
- **Ejecución tras cambios**:
  - Auth/permisos: `pytest tests/test_auth_*.py`
  - Animes: `pytest tests/test_animes.py`
  - Suite completa: `pytest`
- **No ignores tests fallidos** — investiga la causa antes de seguir.

## Flujo de trabajo del agente

**Antes de modificar código**:
1. Inspecciona el código relevante y entiende el contexto.
2. Identifica dependencias y posibles efectos secundarios.
3. Haz el cambio más pequeño que resuelva la tarea.

**Después de modificar código**:
1. Ejecuta tests relevantes.
2. Ejecuta `ruff check .`.
3. Revisa `git diff` y `git status`.
4. Verifica que no existan cambios no relacionados con la tarea.
5. Antes de finalizar una tarea, verifica que `git diff` contenga únicamente cambios relacionados con la tarea.

## Git

- **Rama principal**: `master`.
- **No commits automáticos** — deja cambios listos para revisión.
- **No push automático** — espera autorización explícita.
- **No descartes cambios** del usuario sin autorización.
- **No operaciones destructivas** (reset, checkout, clean) sin autorización.

## Alcance y límites

- **Soluciones simples y mantenibles** — evita overengineering.
- **No nuevas herramientas/dependencias/linters/type-checkers** salvo que la tarea lo requiera.
- **No modifiques archivos no relacionados** con la tarea.
- **Decisiones arquitectónicas importantes**: detente y presenta opciones antes de implementar.