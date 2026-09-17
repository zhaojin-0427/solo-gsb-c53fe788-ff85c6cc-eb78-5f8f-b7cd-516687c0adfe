"""Runtime configuration, sourced from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

DEFAULT_DATABASE_URL = "postgresql+psycopg2://gateway:gateway@localhost:5432/gateway"
DEFAULT_DEV_HMAC_KEY = "dev-only-insecure-key-change-me"


@dataclass(frozen=True)
class Settings:
    database_url: str
    hmac_key: str
    idempotency_lock_timeout_ms: int
    log_level: str
    db_startup_retries: int
    db_startup_retry_delay_seconds: float

    @property
    def hmac_key_is_default(self) -> bool:
        return self.hmac_key == DEFAULT_DEV_HMAC_KEY


@lru_cache
def get_settings() -> Settings:
    return Settings(
        database_url=os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL),
        hmac_key=os.environ.get("MASKING_HMAC_KEY", DEFAULT_DEV_HMAC_KEY),
        idempotency_lock_timeout_ms=int(
            os.environ.get("IDEMPOTENCY_LOCK_TIMEOUT_MS", "15000")
        ),
        log_level=os.environ.get("LOG_LEVEL", "INFO"),
        db_startup_retries=int(os.environ.get("DB_STARTUP_RETRIES", "30")),
        db_startup_retry_delay_seconds=float(
            os.environ.get("DB_STARTUP_RETRY_DELAY_SECONDS", "1")
        ),
    )
