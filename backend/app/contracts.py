from __future__ import annotations

from typing import Any, Literal, Protocol
from pydantic import BaseModel, Field, field_validator


class HistoryMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=4000)


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


class QueryPreparer(Protocol):
    async def prepare(self, message: str, history: list[HistoryMessage]) -> PreparedQuery: ...


class EmbeddingProvider(Protocol):
    def embed(self, text: str) -> list[float]: ...
    def check(self) -> None: ...


class VectorRepository(Protocol):
    def search(self, vector: list[float], top_k: int, cve_ids: list[str]) -> list[Source]: ...
    def descriptions(self, cve_ids: list[str]) -> list[Source]: ...
    def check(self) -> dict[str, Any]: ...


class LLMProvider(Protocol):
    resolved_model: str
    async def chat(self, system: str, user: str, *, max_tokens: int) -> str: ...
    async def check(self) -> bool: ...
