"""Application entrypoint."""
from __future__ import annotations

import re
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text

from . import errors
from .config import get_settings
from .db import Base, get_engine, init_engine
from .logging_config import configure_logging, get_logger
from .routers import policies as policies_router
from .routers import transform as transform_router

settings = get_settings()
configure_logging(settings.log_level)
logger = get_logger("gateway")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")

app = FastAPI(
    title="JSON Masking Gateway",
    version="1.0.0",
    docs_url="/docs",
    openapi_url="/openapi.json",
)


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    incoming = request.headers.get("x-request-id", "")
    request_id = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex
    request.state.request_id = request_id
    try:
        response = await call_next(request)
    except Exception:
        # Let the exception handlers below deal with known types; anything
        # else becomes a generic 500 without leaking details.
        logger.error(
            "unhandled_exception",
            extra={"request_id": request_id, "error_code": errors.INTERNAL_ERROR},
        )
        response = JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": errors.INTERNAL_ERROR,
                    "message": "internal error",
                    "request_id": request_id,
                }
            },
        )
    response.headers["X-Request-Id"] = request_id
    logger.info(
        "request_completed",
        extra={
            "request_id": request_id,
            "method": request.method,
            "route": request.url.path,
            "status_code": response.status_code,
        },
    )
    return response


@app.exception_handler(errors.ApiError)
async def api_error_handler(request: Request, exc: errors.ApiError):
    request_id = getattr(request.state, "request_id", None) or uuid.uuid4().hex
    logger.info(
        "api_error",
        extra={"request_id": request_id, "error_code": exc.code},
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {"code": exc.code, "message": exc.message, "request_id": request_id}
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    request_id = getattr(request.state, "request_id", None) or uuid.uuid4().hex
    # Sanitized: only field locations and error types — never input values.
    fields = [
        {"loc": [str(p) for p in e.get("loc", ())], "type": e.get("type", "")}
        for e in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": errors.VALIDATION_FAILED,
                "message": "request validation failed",
                "request_id": request_id,
                "fields": fields,
            }
        },
    )


@app.get("/healthz", tags=["meta"])
def healthz():
    with get_engine().connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"status": "ok"}


@app.on_event("startup")
def startup() -> None:
    if settings.hmac_key_is_default:
        logger.warning(
            "insecure_default_hmac_key",
            extra={"error_code": "CONFIG_DEFAULT_HMAC_KEY"},
        )
    init_engine()
    engine = get_engine()
    last_exc = None
    for attempt in range(settings.db_startup_retries):
        try:
            Base.metadata.create_all(engine)
            logger.info("database_ready")
            return
        except Exception as exc:  # noqa: BLE001 - retry until the DB is up
            last_exc = exc
            time.sleep(settings.db_startup_retry_delay_seconds)
    logger.error(
        "database_unavailable",
        extra={"error_code": "DB_UNAVAILABLE"},
    )
    raise RuntimeError("database unavailable after retries") from last_exc


app.include_router(policies_router.router)
app.include_router(transform_router.router)
