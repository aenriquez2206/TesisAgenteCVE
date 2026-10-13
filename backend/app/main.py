from __future__ import annotations

import asyncio
import logging
import uuid
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.adapters.chroma_repository import ChromaRepository
from app.adapters.embeddings import OnnxEmbeddings
from app.adapters.model_runner import DockerModelRunner
from app.config import Settings
from app.errors import AppError
from app.logging_config import configure
from app.services.chat import ChatService
from app.services.query_preparer import LocalQueryPreparer
from app.api.routes import router


settings = Settings.from_env()
configure(settings.log_level)
log = logging.getLogger("cve.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    llm = DockerModelRunner(settings.llm_base_url, settings.llm_model, settings.llm_timeout, settings.model_cache_seconds)
    app.state.llm = llm
    app.state.service = ChatService(settings, LocalQueryPreparer(llm, settings.preparation_tokens), OnnxEmbeddings(settings.embedding_hash, settings.embedding_tokenizer_hash),
                                    ChromaRepository(settings), llm)
    repository = app.state.service.repository
    async def warm(name, check):
        started = time.monotonic()
        try:
            await asyncio.wait_for(asyncio.to_thread(check), settings.health_timeout)
            log.info("startup_ready", extra={"fields": {"dependency": name,
                "duration_ms": round((time.monotonic()-started)*1000)}})
        except Exception as exc:
            log.warning("startup_unavailable", extra={"fields": {"dependency": name,
                "duration_ms": round((time.monotonic()-started)*1000),
                "error": getattr(exc, "code", type(exc).__name__)}})
    await asyncio.gather(warm("embeddings", app.state.service.embeddings.check), warm("collection", repository.check))
    try:
        yield
    finally:
        await llm.close()
        await asyncio.to_thread(repository.close)


app = FastAPI(title="CVE Intelligence API", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins),
                   allow_methods=["GET", "POST"], allow_headers=["Content-Type"])


@app.exception_handler(AppError)
async def app_error_handler(request: Request, error: AppError):
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    log.warning("api_error", extra={"fields": {"request_id": request_id, "code": error.code}})
    return JSONResponse(status_code=error.status, content={"request_id": request_id,
                       "code": error.code, "message": error.message})


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, error: RequestValidationError):
    return JSONResponse(status_code=422, content={"request_id": getattr(request.state, "request_id", str(uuid.uuid4())),
                       "code": "invalid_request", "message": "La consulta o el historial no son válidos"})


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, error: Exception):
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    log.error("unexpected_error", extra={"fields": {"request_id": request_id, "error": type(error).__name__}})
    return JSONResponse(status_code=500, headers={"X-Request-ID": request_id},
                        content={"request_id": request_id, "code": "internal_error", "message": "No se pudo completar la solicitud"})


@app.middleware("http")
async def request_ids(request: Request, call_next):
    request.state.request_id = str(uuid.uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    return response


app.include_router(router)
