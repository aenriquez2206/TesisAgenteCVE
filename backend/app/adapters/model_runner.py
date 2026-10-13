from __future__ import annotations

import httpx
from app.errors import AppError


class DockerModelRunner:
    def __init__(self, base_url: str, model: str, timeout: float) -> None:
        self.model = model
        self.resolved_model = model
        self.client = httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=httpx.Timeout(timeout, connect=5.0))

    async def close(self) -> None:
        await self.client.aclose()

    async def check(self) -> bool:
        try:
            response = await self.client.get("/engines/v1/models" if not self.client.base_url.path.endswith("/v1/") else "models")
            response.raise_for_status()
            available = [item["id"] for item in response.json().get("data", [])]
            matches = [name for name in available if name == self.model or name.endswith("/" + self.model)]
            if len(matches) != 1:
                return False
            self.resolved_model = matches[0]
            return True
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            return False

    async def chat(self, system: str, user: str, *, max_tokens: int) -> str:
        if self.resolved_model == self.model and not await self.check():
            raise AppError("llm_unavailable", "El modelo local no está disponible")
        try:
            response = await self.client.post("chat/completions", json={
                "model": self.resolved_model,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "temperature": 0.1,
                "max_tokens": max_tokens,
                "stream": False,
            })
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            if not isinstance(content, str) or not content.strip():
                raise ValueError("Respuesta vacía")
            return content.strip()
        except httpx.TimeoutException as exc:
            raise AppError("llm_timeout", "El modelo local agotó el tiempo de espera", 504) from exc
        except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError) as exc:
            raise AppError("llm_error", "El modelo local devolvió una respuesta inválida", 502) from exc
