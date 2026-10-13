from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    chroma_host: str = "localhost"
    chroma_port: int = 8001
    chroma_collection: str = "catalogo_cve_2023_2026"
    chroma_tenant: str = "default_tenant"
    chroma_database: str = "default_database"
    llm_base_url: str = "http://localhost:12434/engines/v1"
    llm_model: str = "ministral3:8B-Q4_K_M"
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    embedding_hash: str = "4f148ba8ae9c2c7fbee4af2b132db8d06c6a6545b47fc83bbb98c3d22b8393e6"
    embedding_tokenizer_hash: str = "9114256b104cca80e04367526f03f46aa3c443c2ed174904142a73bbf13b9fbb"
    top_k: int = 8
    context_chars: int = 6000
    llm_timeout: float = 120.0
    chroma_timeout: float = 15.0
    health_timeout: float = 5.0
    embedding_timeout: float = 30.0
    preparation_tokens: int = 120
    answer_tokens: int = 220
    comparison_tokens: int = 350
    collection_cache_seconds: float = 60.0
    model_cache_seconds: float = 60.0
    cors_origins: tuple[str, ...] = ("http://localhost:5173",)
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> Settings:
        values = {}
        for name in cls.__dataclass_fields__:
            raw = os.getenv(name.upper())
            if raw is None:
                continue
            if name in ("chroma_port", "top_k", "context_chars", "preparation_tokens", "answer_tokens", "comparison_tokens"):
                values[name] = int(raw)
            elif name in ("llm_timeout", "chroma_timeout", "health_timeout", "embedding_timeout", "collection_cache_seconds", "model_cache_seconds"):
                values[name] = float(raw)
            elif name == "cors_origins":
                values[name] = tuple(x.strip() for x in raw.split(",") if x.strip())
            else:
                values[name] = raw
        result = cls(**values)
        if result.top_k < 1 or result.top_k > 30 or result.context_chars < 500:
            raise ValueError("TOP_K o CONTEXT_CHARS fuera de rango")
        if any(not 0 < value <= 600 for value in (result.llm_timeout, result.chroma_timeout,
                                                 result.health_timeout, result.embedding_timeout)):
            raise ValueError("Timeout fuera de rango (0, 600]")
        if not 1 <= result.chroma_port <= 65535 or result.context_chars > 100000:
            raise ValueError("Puerto o presupuesto de contexto inválido")
        if any(not 1 <= value <= 4096 for value in (result.preparation_tokens, result.answer_tokens, result.comparison_tokens)):
            raise ValueError("Presupuesto de salida inválido")
        if any(not 0 < value <= 600 for value in (result.collection_cache_seconds, result.model_cache_seconds)):
            raise ValueError("Duración de caché inválida")
        return result
