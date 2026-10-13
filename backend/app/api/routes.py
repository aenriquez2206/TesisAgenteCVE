import asyncio
from fastapi import APIRouter, Request
from app.contracts import ChatRequest, ChatResponse, HealthResponse
from app.errors import AppError

router = APIRouter(prefix="/api")


@router.post("/chat", response_model=ChatResponse)
async def chat(body: ChatRequest, request: Request):
    work = asyncio.create_task(request.app.state.service.run(body, request.state.request_id))
    stop_watching = asyncio.Event()
    async def disconnected():
        # FastAPI has already consumed the JSON body. Wait for the disconnect
        # event directly: is_disconnected's canceled polling scope can miss it
        # through BaseHTTPMiddleware's receive wrapper.
        while not stop_watching.is_set():
            message = await request.receive()
            if message["type"] == "http.disconnect":
                return
    watcher = asyncio.create_task(disconnected())
    try:
        await asyncio.wait((work, watcher), return_when=asyncio.FIRST_COMPLETED)
        if work.done():
            return await work
        raise AppError("client_disconnected", "El cliente cerró la solicitud", 499)
    finally:
        # The explicit signal also ends a receive wrapper that suppresses a
        # concurrent cancellation and returns a final message instead.
        stop_watching.set()
        work.cancel()
        watcher.cancel()
        await asyncio.gather(work, watcher, return_exceptions=True)


@router.get("/health", response_model=HealthResponse)
async def health(request: Request):
    service = request.app.state.service
    settings = service.settings
    result = HealthResponse(collection=settings.chroma_collection, model=settings.llm_model)

    async def chroma():
        try:
            await asyncio.wait_for(asyncio.to_thread(service.repository.ping), settings.health_timeout)
            result.chroma = "available"
        except Exception as exc:
            result.chroma_reason = getattr(exc, "code", "chroma_unavailable")
            result.collection_reason = "chroma_unavailable"
            return
        try:
            details = await asyncio.wait_for(asyncio.to_thread(service.repository.check), settings.health_timeout)
            result.collection_status = "available"
            result.document_count = details["count"]
        except Exception as exc:
            result.collection_reason = getattr(exc, "code", "collection_unavailable")

    async def embeddings():
        try:
            await asyncio.wait_for(asyncio.to_thread(service.embeddings.check), settings.health_timeout)
            result.embeddings = "available"
        except Exception as exc:
            result.embeddings_reason = getattr(exc, "code", "embedding_unavailable")

    async def llm():
        try:
            if await asyncio.wait_for(service.llm.check(), settings.health_timeout):
                result.llm = "available"
            else:
                result.llm_reason = "llm_unavailable"
        except Exception:
            result.llm_reason = "llm_unavailable"

    await asyncio.gather(chroma(), embeddings(), llm())
    return result
