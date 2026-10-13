"""Bounded HTTP transport for the pinned Chroma 1.5.9 client.

HttpClient performs network calls during construction with timeout=None. Build
its HTTP API first, bound the session, and wrap collection models using the same
SDK Collection class. This compatibility shim must be tested on SDK upgrades.
"""
import httpx
from chromadb.api import ServerAPI
from chromadb.api.models.Collection import Collection
from chromadb.config import Settings, System


class BoundedHttpClient:
    def __init__(self, host: str, port: int, tenant: str, database: str, timeout: float):
        self.tenant, self.database = tenant, database
        self.system = System(Settings(chroma_api_impl="chromadb.api.fastapi.FastAPI",
            chroma_server_host=host, chroma_server_http_port=port, anonymized_telemetry=False))
        self.api = self.system.instance(ServerAPI)
        self.api._session.timeout = httpx.Timeout(timeout)
        self.system.start()

    def heartbeat(self):
        return self.api.heartbeat()

    def get_collection(self, name: str, embedding_function=None):
        model = self.api.get_collection(name, tenant=self.tenant, database=self.database)
        return Collection(client=self.api, model=model, embedding_function=embedding_function)

    def close(self):
        self.system.stop()
