from __future__ import annotations

import asyncio
import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.adapters.chroma_repository import ChromaRepository
from app.adapters.embeddings import OnnxEmbeddings
from app.adapters.model_runner import DockerModelRunner
from app.config import Settings
from app.contracts import ChatRequest, ChatResponse
from app.errors import AppError
from app.logging_config import configure
from app.services.chat import ChatService
from app.services.query_preparer import LocalQueryPreparer


settings = Settings.from_env()
configure(settings.log_level)
log = logging.getLogger("cve.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    llm = DockerModelRunner(settings.llm_base_url, settings.llm_model, settings.llm_timeout)
    app.state.llm = llm
    app.state.service = ChatService(settings, LocalQueryPreparer(llm), OnnxEmbeddings(settings.embedding_hash),
                                    ChromaRepository(settings), llm)
    try:
        yield
    finally:
        await llm.close()


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


@app.middleware("http")
async def request_ids(request: Request, call_next):
    request.state.request_id = str(uuid.uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    return response


@app.post("/api/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, raw: Request):
    return await raw.app.state.service.run(request, raw.state.request_id)


@app.get("/api/health")
async def health(raw: Request):
    service = raw.app.state.service
    result = {"backend": "available", "chroma": "unavailable", "collection": settings.chroma_collection,
              "embeddings": "unavailable", "llm": "unavailable", "model": settings.llm_model}
    try:
        details = await asyncio.wait_for(asyncio.to_thread(service.repository.check), timeout=settings.chroma_timeout)
        result.update(chroma="available", document_count=details["count"])
    except Exception as exc:
        result["chroma_reason"] = getattr(exc, "code", "chroma_unavailable")
    try:
        await asyncio.to_thread(service.embeddings.check)
        result["embeddings"] = "available"
    except Exception as exc:
        result["embeddings_reason"] = getattr(exc, "code", "embedding_incompatible")
    if await raw.app.state.llm.check():
        result["llm"] = "available"
    return result
