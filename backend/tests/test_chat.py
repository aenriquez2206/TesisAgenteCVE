import unittest

from app.config import Settings
from app.contracts import ChatRequest, PreparedQuery, Source
from app.errors import AppError
from app.services.chat import ChatService


class Preparer:
    async def prepare(self, message, history):
        return PreparedQuery(language="es" if "Qué" in message else "en",
                             query_en="What is CVE-2023-27849?" if "Qué" in message else message,
                             status="translated" if "Qué" in message else "reused")


class Embeddings:
    def embed(self, text):
        self.query = text
        return [0.1] * 384


class Repository:
    def __init__(self, found=True):
        self.found = found
        self.calls = []

    def search(self, vector, top_k, cve_ids):
        self.calls.append((top_k, cve_ids))
        if not self.found:
            return []
        return [Source(id="doc-1", document_excerpt="CVE-2023-27849 | nvd\nRemote code execution.",
                       metadata={"content_type": "nvd", "cve_id": "CVE-2023-27849", "base_score": 9.8},
                       cve_id="CVE-2023-27849", source="nvd", distance=0.2)]

    def descriptions(self, cve_id, kind):
        return []

    def grouped(self, cve_id, kinds):
        return []


class LLM:
    resolved_model = "docker.io/ai/ministral3:8B-Q4_K_M"
    answer = "Remote code execution [1]."

    async def chat(self, system, user, *, max_tokens):
        return self.answer


class ChatTests(unittest.IsolatedAsyncioTestCase):
    async def test_spanish_query_filters_cve_and_keeps_original(self):
        embedding, repository = Embeddings(), Repository()
        service = ChatService(Settings(), Preparer(), embedding, repository, LLM())
        response = await service.run(ChatRequest(message="¿Qué es CVE-2023-27849?"), "test-request")
        self.assertEqual(embedding.query, "What is CVE-2023-27849?")
        self.assertEqual(repository.calls, [(8, ["CVE-2023-27849"])])
        self.assertEqual(response.trace.detected_language, "es")
        self.assertEqual(response.trace.original_question, "¿Qué es CVE-2023-27849?")
        self.assertEqual(response.request_id, "test-request")
        self.assertEqual(len(response.sources), 1)

    async def test_no_results_never_calls_llm(self):
        llm = LLM()
        async def unexpected(*args, **kwargs):
            raise AssertionError("LLM must not generate unsupported facts")
        llm.chat = unexpected
        service = ChatService(Settings(), Preparer(), Embeddings(), Repository(found=False), llm)
        response = await service.run(ChatRequest(message="Unknown vulnerability"))
        self.assertEqual(response.sources, [])
        self.assertEqual(response.trace.retrieved_count, 0)

    async def test_invalid_citations_fail_closed(self):
        llm = LLM()
        llm.answer = "Unsupported statement [9]."
        service = ChatService(Settings(), Preparer(), Embeddings(), Repository(), llm)
        with self.assertRaises(AppError) as raised:
            await service.run(ChatRequest(message="What is CVE-2023-27849?"))
        self.assertEqual(raised.exception.code, "invalid_citations")

    async def test_unsupported_score_fails_closed(self):
        llm = LLM()
        llm.answer = "The score may reach 10.0 [1]."
        service = ChatService(Settings(), Preparer(), Embeddings(), Repository(), llm)
        with self.assertRaises(AppError) as raised:
            await service.run(ChatRequest(message="What is CVE-2023-27849?"))
        self.assertEqual(raised.exception.code, "unsupported_numbers")

    async def test_generic_cve_question_excludes_generic_attack_patterns(self):
        repository = Repository()
        def mixed(vector, top_k, cve_ids):
            return [Source(id="capec-1", document_excerpt="Command injection",
                           metadata={"content_type": "capec", "cve_id": "CVE-2023-27849"},
                           cve_id="CVE-2023-27849", source="capec", distance=0.1),
                    Source(id="nvd-1", document_excerpt="Remote code execution via child_process",
                           metadata={"content_type": "nvd", "cve_id": "CVE-2023-27849"},
                           cve_id="CVE-2023-27849", source="nvd", distance=0.2)]
        repository.search = mixed
        service = ChatService(Settings(), Preparer(), Embeddings(), repository, LLM())
        response = await service.run(ChatRequest(message="What is CVE-2023-27849?"))
        self.assertEqual([source.id for source in response.sources], ["nvd-1"])

    async def test_unretrieved_link_is_not_presented_as_source(self):
        llm = LLM()
        llm.answer = "Remote code execution [1]. [Report](https://example.org/unsupported)"
        service = ChatService(Settings(), Preparer(), Embeddings(), Repository(), llm)
        response = await service.run(ChatRequest(message="What is CVE-2023-27849?"))
        self.assertNotIn("https://example.org/unsupported", response.answer)


if __name__ == "__main__":
    unittest.main()
