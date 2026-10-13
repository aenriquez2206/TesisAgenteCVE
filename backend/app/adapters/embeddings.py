from __future__ import annotations

import hashlib
import threading
from tokenizers import Tokenizer
from pathlib import Path

import numpy as np
from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2

from app.errors import AppError


class OnnxEmbeddings:
    def __init__(self, expected_hash: str, tokenizer_hash: str = "9114256b104cca80e04367526f03f46aa3c443c2ed174904142a73bbf13b9fbb") -> None:
        self.model = ONNXMiniLM_L6_V2(preferred_providers=["CPUExecutionProvider"])
        self.expected_hash = expected_hash
        self.tokenizer_hash = tokenizer_hash
        self._checked = False
        self._lock = threading.RLock()

    def check(self) -> None:
        with self._lock:
            self._initialize()

    def _initialize(self) -> None:
        if self._checked:
            return
        try:
            self.model._download_model_if_not_exists()
            path = Path(self.model.DOWNLOAD_PATH) / self.model.EXTRACTED_FOLDER_NAME / "model.onnx"
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            if digest.hexdigest() != self.expected_hash:
                raise ValueError("Hash de modelo diferente al usado durante la ingesta")
            self.tokenizer = Tokenizer.from_str(self.model.tokenizer.to_str())
            self.tokenizer.no_padding()
            self.tokenizer.no_truncation()
            if hashlib.sha256(self.tokenizer.to_str().encode()).hexdigest() != self.tokenizer_hash:
                raise ValueError("Tokenizador diferente al usado durante la ingesta")
            self._validate(self.model(["Model readiness check."])[0])
            self._checked = True
        except Exception as exc:
            raise AppError("embedding_incompatible", "No se pudo verificar el modelo de embeddings") from exc

    @staticmethod
    def _validate(value) -> list[float]:
        vector = np.asarray(value, dtype=np.float32)
        if vector.shape != (384,) or not np.isfinite(vector).all() or abs(float(np.linalg.norm(vector)) - 1) > 0.01:
            raise ValueError("Vector incompatible")
        return vector.tolist()

    def embed(self, text: str) -> list[float]:
        self.check()
        if len(self.tokenizer.encode(text).ids) > self.model.max_tokens():
            raise AppError("query_too_long", "La consulta inglesa supera el límite del modelo de embeddings", 422)
        try:
            with self._lock:
                return self._validate(self.model([text])[0])
        except AppError:
            raise
        except Exception as exc:
            raise AppError("embedding_incompatible", "No se pudo generar un embedding compatible") from exc
