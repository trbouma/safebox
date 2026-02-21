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
