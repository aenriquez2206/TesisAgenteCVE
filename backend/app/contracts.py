from __future__ import annotations

from typing import Any, Literal, Protocol
from pydantic import BaseModel, Field, field_validator


class HistoryMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=4000)

    @field_validator("content")
    @classmethod
    def nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("El historial no puede contener mensajes vacíos")
        return value


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    conversation_id: str | None = Field(default=None, max_length=80)
    history: list[HistoryMessage] = Field(default_factory=list, max_length=10)

    @field_validator("message", "conversation_id")
    @classmethod
    def meaningful(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("El campo no puede estar vacío")
        return value

    @field_validator("history")
    @classmethod
    def limited_history(cls, value: list[HistoryMessage]) -> list[HistoryMessage]:
        if sum(len(item.content) for item in value) > 12000:
            raise ValueError("El historial supera 12000 caracteres")
        return value


class Source(BaseModel):
    id: str
    document_excerpt: str
    metadata: dict[str, Any]
    cve_id: str | None = None
    source: str | None = None
    url: str | None = None
    distance: float | None = None


class Trace(BaseModel):
    detected_language: Literal["es", "en"]
    original_question: str
    search_query_en: str
    translation_status: str
    retrieval_method: str
    retrieved_count: int
    used_count: int
    collection: str
    model: str
    resolved_model: str
    timings_ms: dict[str, int]
    preparation_status: Literal["complete"] = "complete"
    retrieval_status: Literal["complete", "empty"] = "complete"
    generation_status: Literal["complete", "skipped"] = "complete"
    route: str | None = None
    template_answer: bool = False
    llm_calls: int = 0
    retries: int = 0
    chroma_operations: int = 0


class ChatResponse(BaseModel):
    answer: str
    conversation_id: str
    request_id: str
    sources: list[Source]
    trace: Trace


class PreparedQuery(BaseModel):
    language: Literal["es", "en"]
    query_en: str
    status: str
    intent: str | None = None
    llm_calls: int = 0
    retries: int = 0


class QueryPreparer(Protocol):
    async def prepare(self, message: str, history: list[HistoryMessage]) -> PreparedQuery: ...


class EmbeddingProvider(Protocol):
    def embed(self, text: str) -> list[float]: ...
    def check(self) -> None: ...


class VectorRepository(Protocol):
    def search(self, vector: list[float], top_k: int, cve_ids: list[str]) -> list[Source]: ...
    def descriptions(self, cve_id: str, kind: str) -> list[Source]: ...
    def grouped(self, cve_id: str, kinds: tuple[str, ...]) -> list[Source]: ...
    def ping(self) -> None: ...
    def check(self) -> dict[str, Any]: ...


class LLMProvider(Protocol):
    resolved_model: str
    async def chat(self, system: str, user: str, *, max_tokens: int) -> str: ...
    async def check(self) -> bool: ...


class HealthResponse(BaseModel):
    backend: Literal["available"] = "available"
    chroma: Literal["available", "unavailable"] = "unavailable"
    collection: str
    collection_status: Literal["available", "unavailable"] = "unavailable"
    embeddings: Literal["available", "unavailable"] = "unavailable"
    llm: Literal["available", "unavailable"] = "unavailable"
    model: str
    document_count: int | None = None
    chroma_reason: str | None = None
    collection_reason: str | None = None
    embeddings_reason: str | None = None
    llm_reason: str | None = None
