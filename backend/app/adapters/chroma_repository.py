from __future__ import annotations

import math
import threading
import time
import httpx
from chromadb.errors import NotFoundError
from app.adapters.bounded_chroma import BoundedHttpClient
from typing import Any


from app.config import Settings
from app.contracts import Source
from app.errors import AppError
from app.services.metrics import chroma_operation


class ChromaRepository:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client = None
        self._lock = threading.RLock()
        self._cached_collection = None
        self._validated_until = 0.0

    def _client(self):
        with self._lock:
            if self.client is None:
                try:
                    self.client = BoundedHttpClient(
                        self.settings.chroma_host, self.settings.chroma_port,
                        self.settings.chroma_tenant, self.settings.chroma_database, self.settings.chroma_timeout)
                except Exception as exc:
                    raise AppError("chroma_unavailable", "ChromaDB no está disponible") from exc
        return self.client

    def close(self) -> None:
        self.invalidate()
        if self.client is not None:
            self.client.close()

    def ping(self) -> None:
        try:
            chroma_operation()
            self._client().heartbeat()
        except AppError:
            self.invalidate()
            raise
        except httpx.TimeoutException as exc:
            self.invalidate()
            raise AppError("chroma_timeout", "ChromaDB agotó el tiempo de espera", 504) from exc
        except Exception as exc:
            self.invalidate()
            raise AppError("chroma_unavailable", "ChromaDB no está disponible") from exc

    def invalidate(self) -> None:
        with self._lock:
            self._cached_collection = None
            self._validated_until = 0.0

    def _collection(self, *, refresh: bool = False):
        try:
            with self._lock:
                if not refresh and self._cached_collection is not None and time.monotonic() < self._validated_until:
                    return self._cached_collection
                chroma_operation()
                self._client().heartbeat()
                chroma_operation()
                collection = self._client().get_collection(self.settings.chroma_collection, embedding_function=None)
                metadata = collection.metadata or {}
                compatible = (metadata.get("status") == "validated"
                              and metadata.get("dimension") == 384
                              and metadata.get("embedding_model") == self.settings.embedding_model
                              and collection.configuration["hnsw"]["space"] == "cosine")
                if not compatible:
                    raise AppError("collection_incompatible", "La colección no coincide con la indexación esperada")
                self._cached_collection = collection
                self._validated_until = time.monotonic() + self.settings.collection_cache_seconds
                return collection
        except NotFoundError as exc:
            self.invalidate()
            raise AppError("collection_missing", "La colección configurada no existe") from exc
        except AppError:
            self.invalidate()
            raise
        except httpx.TimeoutException as exc:
            self.invalidate()
            raise AppError("chroma_timeout", "ChromaDB agotó el tiempo de espera", 504) from exc
        except Exception as exc:
            self.invalidate()
            raise AppError("chroma_unavailable", "No se pudo consultar ChromaDB") from exc

    def check(self) -> dict[str, Any]:
        try:
            collection = self._collection(refresh=True)
            chroma_operation()
            return {"available": True, "count": collection.count(), "collection": collection.name}
        except AppError:
            self.invalidate()
            raise
        except httpx.TimeoutException as exc:
            self.invalidate()
            raise AppError("chroma_timeout", "ChromaDB agotó el tiempo de espera", 504) from exc
        except Exception as exc:
            self.invalidate()
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
            collection = self._collection()
            kwargs: dict[str, Any] = {"query_embeddings": [vector], "n_results": top_k,
                                      "include": ["documents", "metadatas", "distances"]}
            if cve_ids:
                kwargs["where"] = {"cve_id": cve_ids[0]} if len(cve_ids) == 1 else {"cve_id": {"$in": cve_ids}}
            chroma_operation()
            result = collection.query(**kwargs)
            return [self._source(i, d, m, distance) for i, d, m, distance in zip(
                result["ids"][0], result["documents"][0], result["metadatas"][0], result["distances"][0])]
        except AppError:
            self.invalidate()
            raise
        except httpx.TimeoutException as exc:
            self.invalidate()
            raise AppError("chroma_timeout", "ChromaDB agotó el tiempo de espera", 504) from exc
        except Exception as exc:
            self.invalidate()
            raise AppError("retrieval_error", "Falló la recuperación en ChromaDB") from exc

    def descriptions(self, cve_id: str, kind: str) -> list[Source]:
        return self.grouped(cve_id, (kind,))

    def grouped(self, cve_id: str, kinds: tuple[str, ...]) -> list[Source]:
        """Read requested kinds together, retaining up to three records per kind.

        Remove satisfied kinds from the filter, restarting pagination and
        deduplicating IDs. This avoids scanning thousands of CAPEC chunks just
        because a CVE has only one NVD description. The service bounds concurrent
        CVEs to four.
        """
        if not kinds:
            return []
        try:
            collection = self._collection()
            buckets: dict[str, list[Source]] = {kind: [] for kind in kinds}
            offset, page_size = 0, 64
            active_kinds = list(kinds)
            seen: set[str] = set()
            deadline = time.monotonic() + self.settings.chroma_timeout
            while True:
                if time.monotonic() >= deadline:
                    raise httpx.TimeoutException("Grouped retrieval deadline exceeded")
                missing = [kind for kind in kinds if len(buckets[kind]) < 3]
                if not missing:
                    break
                if missing != active_kinds:
                    active_kinds, offset = missing, 0
                chroma_operation()
                page = collection.get(where={"$and": [{"cve_id": cve_id},
                    {"content_type": {"$in": active_kinds}}]}, limit=page_size,
                    offset=offset, include=["documents", "metadatas"])
                for i, d, m in zip(page["ids"], page["documents"], page["metadatas"]):
                    kind = (m or {}).get("content_type")
                    if i not in seen and kind in buckets and len(buckets[kind]) < 3:
                        seen.add(i)
                        buckets[kind].append(self._source(i, d, m, None))
                if len(page["ids"]) < page_size:
                    break
                offset += page_size
            return [source for kind in kinds for source in buckets[kind]]
        except AppError:
            self.invalidate()
            raise
        except httpx.TimeoutException as exc:
            self.invalidate()
            raise AppError("chroma_timeout", "ChromaDB agotó el tiempo de espera", 504) from exc
        except Exception as exc:
            self.invalidate()
            raise AppError("retrieval_error", "Falló la lectura de descripciones en ChromaDB") from exc
