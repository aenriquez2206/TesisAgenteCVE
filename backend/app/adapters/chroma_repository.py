from __future__ import annotations

import math
from typing import Any

import chromadb

from app.config import Settings
from app.contracts import Source
from app.errors import AppError


class ChromaRepository:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client = None

    def _client(self):
        if self.client is None:
            self.client = chromadb.HttpClient(
                host=self.settings.chroma_host,
                port=self.settings.chroma_port,
                tenant=self.settings.chroma_tenant,
                database=self.settings.chroma_database,
            )
        return self.client

    def _collection(self):
        try:
            return self._client().get_collection(self.settings.chroma_collection, embedding_function=None)
        except Exception as exc:
            raise AppError("collection_unavailable", "No se pudo abrir la colección Chroma") from exc

    def check(self) -> dict[str, Any]:
        try:
            self._client().heartbeat()
            collection = self._collection()
            metadata = collection.metadata or {}
            compatible = (metadata.get("status") == "validated"
                          and metadata.get("dimension") == 384
                          and metadata.get("embedding_model") == self.settings.embedding_model
                          and collection.configuration["hnsw"]["space"] == "cosine")
            if not compatible:
                raise AppError("collection_incompatible", "La colección no coincide con la indexación esperada")
            return {"available": True, "count": collection.count(), "collection": collection.name}
        except AppError:
            raise
        except Exception as exc:
            raise AppError("chroma_unavailable", "ChromaDB no está disponible") from exc

    @staticmethod
    def _source(identifier: str, document: str | None, metadata: dict[str, Any] | None, distance: float | None) -> Source:
        meta = metadata or {}
        kind = meta.get("content_type")
        url = meta.get("source_url")
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            url = None
        if distance is not None and not math.isfinite(distance):
            distance = None
        return Source(id=identifier, document_excerpt=(document or "")[:2000], metadata=meta,
                      cve_id=meta.get("cve_id"), source=kind, url=url, distance=distance)

    def search(self, vector: list[float], top_k: int, cve_ids: list[str]) -> list[Source]:
        try:
            self.check()
            collection = self._collection()
            kwargs: dict[str, Any] = {"query_embeddings": [vector], "n_results": top_k,
                                      "include": ["documents", "metadatas", "distances"]}
            if cve_ids:
                kwargs["where"] = {"cve_id": cve_ids[0]} if len(cve_ids) == 1 else {"cve_id": {"$in": cve_ids}}
            result = collection.query(**kwargs)
            return [self._source(i, d, m, distance) for i, d, m, distance in zip(
                result["ids"][0], result["documents"][0], result["metadatas"][0], result["distances"][0])]
        except AppError:
            raise
        except Exception as exc:
            raise AppError("retrieval_error", "Falló la recuperación en ChromaDB") from exc

    def descriptions(self, cve_ids: list[str]) -> list[Source]:
        if not cve_ids:
            return []
        try:
            collection = self._collection()
            sources = []
            for cve_id in cve_ids:
                for kind in ("nvd", "cwe", "exploit"):
                    page = collection.get(where={"$and": [{"cve_id": cve_id}, {"content_type": kind}]},
                                          limit=3, include=["documents", "metadatas"])
                    sources.extend(self._source(i, d, m, None) for i, d, m in zip(
                        page["ids"], page["documents"], page["metadatas"]))
            return sources
        except Exception as exc:
            raise AppError("retrieval_error", "Falló la lectura de descripciones en ChromaDB") from exc
