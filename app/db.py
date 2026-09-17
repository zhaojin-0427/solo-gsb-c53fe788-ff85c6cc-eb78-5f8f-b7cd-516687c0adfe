"""SQLAlchemy engine / session management."""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


_engine = None
_SessionLocal = None


def init_engine() -> None:
    global _engine, _SessionLocal
    settings = get_settings()
    _engine = create_engine(settings.database_url, pool_pre_ping=True, pool_size=10)
    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)


def get_engine():
    if _engine is None:
        init_engine()
    return _engine


def get_session_factory():
    if _SessionLocal is None:
        init_engine()
    return _SessionLocal


def get_db():
    """FastAPI dependency yielding a session (caller controls transactions)."""
    factory = get_session_factory()
    db = factory()
    try:
        yield db
    finally:
        db.close()
