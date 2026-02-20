from __future__ import annotations

from collections.abc import Generator

from sqlalchemy.engine.url import make_url
from sqlmodel import Session, create_engine

from app.config import Settings

settings = Settings()
database_url = settings.DATABASE
url = make_url(database_url)

engine_kwargs: dict = {
    "pool_pre_ping": True,
}

# SQLite does not support pool tuning in the same way as networked databases.
if url.get_backend_name().startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs["pool_size"] = settings.DB_POOL_SIZE
    engine_kwargs["max_overflow"] = settings.DB_MAX_OVERFLOW
    engine_kwargs["pool_recycle"] = settings.DB_POOL_RECYCLE_SECONDS
    engine_kwargs["pool_timeout"] = settings.DB_POOL_TIMEOUT_SECONDS

engine = create_engine(database_url, **engine_kwargs)


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session


def ensure_registeredsafebox_uniqueness() -> None:
    """
    Enforce uniqueness for wallet identity keys.
    Raises RuntimeError if existing duplicates are detected.
    """
    duplicate_checks = {
        "npub": """
            SELECT npub, COUNT(*) AS c
            FROM registeredsafebox
            GROUP BY npub
            HAVING COUNT(*) > 1
        """,
        "handle": """
            SELECT handle, COUNT(*) AS c
            FROM registeredsafebox
            GROUP BY handle
            HAVING COUNT(*) > 1
        """,
        "access_key": """
            SELECT access_key, COUNT(*) AS c
            FROM registeredsafebox
            WHERE access_key IS NOT NULL
            GROUP BY access_key
            HAVING COUNT(*) > 1
        """,
    }

    with engine.begin() as conn:
        for field, sql in duplicate_checks.items():
            dup = conn.exec_driver_sql(sql).first()
            if dup:
                raise RuntimeError(
                    f"registeredsafebox has duplicate values for {field}: {dup[0]!r} (count={dup[1]})"
                )

        conn.exec_driver_sql(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_registeredsafebox_npub "
            "ON registeredsafebox (npub)"
        )
        conn.exec_driver_sql(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_registeredsafebox_handle "
            "ON registeredsafebox (handle)"
        )
        conn.exec_driver_sql(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_registeredsafebox_access_key "
            "ON registeredsafebox (access_key) WHERE access_key IS NOT NULL"
        )
