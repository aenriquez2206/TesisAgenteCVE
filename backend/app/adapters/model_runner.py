from __future__ import annotations

import httpx
import asyncio
import time
from app.errors import AppError
from app.services.metrics import current_metrics


class DockerModelRunner:
    def __init__(self, base_url: str, model: str, timeout: float, cache_seconds: float = 60) -> None:
        self.model = model
        self.resolved_model = model
        self.cache_seconds = cache_seconds
        self._resolved_until = 0.0
        self._resolution_lock = asyncio.Lock()
        self._generation_slot = asyncio.Semaphore(1)
        self.client = httpx.AsyncClient(base_url=base_url.rstrip("/") + "/", timeout=httpx.Timeout(timeout, connect=5.0))

    async def close(self) -> None:
        await self.client.aclose()

    async def check(self, *, refresh: bool = True) -> bool:
        async with self._resolution_lock:
            if not refresh and time.monotonic() < self._resolved_until:
                return True
            return await self._resolve()

    async def _resolve(self) -> bool:
        try:
            response = await self.client.get("models")
            response.raise_for_status()
            available = [item["id"] for item in response.json().get("data", [])]
            matches = [name for name in available if name == self.model or name.endswith("/" + self.model)]
            if len(matches) != 1:
                self._resolved_until = 0
                return False
            self.resolved_model = matches[0]
            self._resolved_until = time.monotonic() + self.cache_seconds
            return True
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            self._resolved_until = 0
            return False

    async def chat(self, system: str, user: str, *, max_tokens: int) -> str:
        queued = time.monotonic()
        # One active generation avoids oversubscribing the local GPU. Include queueing
        # in the timeout; canceled callers must not leave unlimited queued work.
        try:
            async with asyncio.timeout(self.client.timeout.read):
                async with self._generation_slot:
                    metrics = current_metrics.get()
                    if metrics is not None:
                        metrics.model_wait_ms += (time.monotonic() - queued) * 1000
                    return await self._chat(system, user, max_tokens=max_tokens)
        except TimeoutError as exc:
            self._resolved_until = 0
            raise AppError("llm_timeout", "El modelo local agotó el tiempo de espera", 504) from exc

    async def _chat(self, system: str, user: str, *, max_tokens: int) -> str:
        if not await self.check(refresh=False):
            raise AppError("llm_unavailable", "El modelo local no está disponible")
        try:
            response = await self.client.post("chat/completions", json={
                "model": self.resolved_model,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "temperature": 0.1,
                "max_tokens": max_tokens,
                "stream": False,
            })
            if response.status_code == 400 and "context" in response.text.lower() and any(
                    word in response.text.lower() for word in ("exceed", "large", "length", "size")):
                raise AppError("llm_context_limit", "La consulta y sus fuentes exceden el contexto del modelo", 422)
            response.raise_for_status()
            choice = response.json()["choices"][0]
            if choice.get("finish_reason") == "length":
                raise AppError("llm_truncated", "El modelo alcanzó el límite de salida; la respuesta no se publicará", 502)
            content = choice["message"]["content"]
            if not isinstance(content, str) or not content.strip():
                raise ValueError("Respuesta vacía")
            return content.strip()
        except httpx.TimeoutException as exc:
            self._resolved_until = 0
            raise AppError("llm_timeout", "El modelo local agotó el tiempo de espera", 504) from exc
        except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError) as exc:
            self._resolved_until = 0
            raise AppError("llm_error", "El modelo local devolvió una respuesta inválida", 502) from exc
