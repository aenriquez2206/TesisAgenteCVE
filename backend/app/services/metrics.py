"""Request-local counters shared with asyncio.to_thread calls."""
from contextvars import ContextVar
from dataclasses import dataclass, field
import threading


@dataclass
class RequestMetrics:
    chroma_operations: int = 0
    model_wait_ms: float = 0
    lock: threading.Lock = field(default_factory=threading.Lock)


current_metrics: ContextVar[RequestMetrics | None] = ContextVar("request_metrics", default=None)


def chroma_operation() -> None:
    metrics = current_metrics.get()
    if metrics is not None:
        with metrics.lock:
            metrics.chroma_operations += 1
