#!/bin/sh
set -eu

if [ "${SKIP_MIGRATIONS:-0}" = "1" ]; then
  exec "$@"
fi

python -c '
import os
from sqlalchemy.engine.url import make_url

db = os.getenv("DATABASE")
if not db:
    print("DB target: DATABASE env var is not set")
else:
    try:
        u = make_url(db)
        backend = u.get_backend_name()
        host = u.host or "local"
        name = (u.database or "").lstrip("/") or "unknown"
        print(f"DB target: backend={backend} host={host} database={name}")
    except Exception as exc:
        print(f"DB target: unable to parse DATABASE env var ({exc})")
'

# Legacy bootstrap compatibility:
# If schema tables already exist but Alembic tracking table does not,
# mark current DB as baseline so upgrade head can proceed.
legacy_schema_detected=0
if python -c '
import os
from sqlalchemy import create_engine, inspect

db = os.getenv("DATABASE")
if not db:
    raise SystemExit(1)

engine = create_engine(db)
insp = inspect(engine)
has_alembic = insp.has_table("alembic_version")
has_app_tables = insp.has_table("registeredsafebox") or insp.has_table("currencyrate")
raise SystemExit(0 if (has_app_tables and not has_alembic) else 1)
'; then
  legacy_schema_detected=1
fi

if [ "$legacy_schema_detected" -eq 1 ]; then
  echo "Detected existing schema without Alembic version table; stamping baseline head..."
  alembic stamp head
fi

max_retries="${ALEMBIC_MAX_RETRIES:-30}"
retry_interval="${ALEMBIC_RETRY_INTERVAL:-2}"
attempt=1

echo "Running database migrations with Alembic..."
while [ "$attempt" -le "$max_retries" ]; do
  if alembic upgrade head; then
    echo "Alembic migrations complete."
    exec "$@"
  fi

  echo "Migration attempt ${attempt}/${max_retries} failed; retrying in ${retry_interval}s..."
  attempt=$((attempt + 1))
  sleep "$retry_interval"
done

echo "Alembic migrations failed after ${max_retries} attempts." >&2
exit 1
