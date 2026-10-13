import asyncio
import json
import unittest
from unittest.mock import Mock, patch

import httpx
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings
from app.contracts import ChatRequest, HistoryMessage, Source
from app.errors import AppError
from app.services.query_preparer import LocalQueryPreparer
from app.services.prompt_builder import select_context, build_prompt
from app.services.chat import ChatService
from app.adapters.model_runner import DockerModelRunner
from app.adapters.chroma_repository import ChromaRepository
from test_chat import Preparer, Embeddings, Repository, LLM


class SequenceLLM(LLM):
    def __init__(self, answers):
        self.answers = iter(answers)
        self.calls = []

    async def chat(self, system, user, *, max_tokens):
        self.calls.append((system, user))
        return next(self.answers)


class PreparationTests(unittest.IsolatedAsyncioTestCase):
    async def test_identifier_inherits_last_user_language_not_ascii(self):
        llm = SequenceLLM([])
        query = await LocalQueryPreparer(llm).prepare('CVE-2023-27849', [
            HistoryMessage(role='user', content='explica el riesgo'),
            HistoryMessage(role='assistant', content='This is an English answer')])
        self.assertEqual(query.language, 'es')
        self.assertEqual(query.status, 'not_required')
        self.assertEqual(llm.calls, [])

    async def test_english_standalone_with_history_preserves_wording(self):
        llm = SequenceLLM([json.dumps({'language': 'en', 'query_en': 'Reworded query'})])
        result = await LocalQueryPreparer(llm).prepare('What vulnerabilities affect Apache?', [HistoryMessage(role='user', content='Hola')])
        self.assertEqual(result.query_en, 'What vulnerabilities affect Apache?')

    async def test_translation_preserves_technical_tokens_and_retries(self):
        llm = SequenceLLM([json.dumps({'language': 'es', 'query_en': 'Risk?'}),
                          json.dumps({'language': 'es', 'query_en': 'What is the risk of CVE-2023-27849 in OpenSSL 1.2.3?'})])
        result = await LocalQueryPreparer(llm).prepare('¿Cuál es el riesgo de CVE-2023-27849 en OpenSSL 1.2.3?', [])
        self.assertIn('OpenSSL 1.2.3', result.query_en)
        self.assertEqual(len(llm.calls), 2)

    async def test_ambiguous_followup_requests_clarification(self):
        llm = SequenceLLM([json.dumps({'language': 'en', 'query_en': 'How is CVE-2023-27849 mitigated?'})])
        with self.assertRaises(AppError) as caught:
            await LocalQueryPreparer(llm).prepare('How is it mitigated?', [HistoryMessage(role='user', content='Compare CVE-2023-27849 and CVE-2024-3094')])
        self.assertEqual(caught.exception.code, 'clarification_required')

    async def test_bad_json_and_lost_identifiers_fail(self):
        for answers in [['bad', '{}'], [json.dumps({'language': 'es', 'query_en': 'What is CVE-2024-3094?'})] * 2]:
            with self.assertRaises(AppError):
                await LocalQueryPreparer(SequenceLLM(answers)).prepare('¿Qué riesgo tiene CVE-2023-27849 en OpenSSL 1.2.3?', [])


class ReliabilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_retry_validates_numbers_and_citations_together(self):
        llm = SequenceLLM(['Remote execution [9].', 'CVSS score 10.0 [1].'])
        service = ChatService(Settings(), Preparer(), Embeddings(), Repository(), llm)
        with self.assertRaises(AppError) as caught:
            await service.run(ChatRequest(message='What is CVE-2023-27849? It has score 10.0'))
        self.assertEqual(caught.exception.code, 'unsupported_numbers')

    async def test_each_lookup_logged_and_no_results_generation_skipped(self):
        service = ChatService(Settings(), Preparer(), Embeddings(), Repository(), LLM())
        with self.assertLogs('cve.retrieval', level='INFO') as captured:
            await service.run(ChatRequest(message='What is CVE-2023-27849?'), 'correlation')
        starts = [r for r in captured.records if r.msg == 'retrieval_start']
        ends = [r for r in captured.records if r.msg == 'retrieval_complete']
        self.assertEqual(len(starts), 2)
        self.assertEqual(len(ends), 2)
        self.assertEqual([r.fields['operation'] for r in starts], ['vector_search', 'grouped_lookup'])
        self.assertTrue(all(r.fields['request_id'] == 'correlation' for r in starts + ends))
        validations = [r for r in captured.records if r.msg == 'generation_validation']
        self.assertEqual(len(validations), 1)
        self.assertTrue(validations[0].fields['valid'])
        self.assertIn('CVE-2023-27849', validations[0].fields['allowed_identifiers'])
        self.assertEqual(validations[0].fields['source_ids'], ['doc-1'])
        service.repository = Repository(False)
        with self.assertLogs('cve.retrieval', level='INFO') as captured:
            result = await service.run(ChatRequest(message='Missing'))
        self.assertEqual(result.trace.generation_status, 'skipped')
        self.assertIn('generation_skipped', [r.msg for r in captured.records])
        self.assertNotIn('generation_complete', [r.msg for r in captured.records])

    async def test_retrieval_failure_logged(self):
        repository = Repository()
        repository.search = Mock(side_effect=AppError('chroma_unavailable', 'offline'))
        service = ChatService(Settings(), Preparer(), Embeddings(), repository, LLM())
        with self.assertLogs('cve.retrieval', level='INFO') as captured:
            with self.assertRaises(AppError):
                await service.run(ChatRequest(message='Test'))
        self.assertEqual(len([r for r in captured.records if r.msg == 'retrieval_failed']), 1)

    async def test_model_runner_paths_and_exact_model_resolution(self):
        requests = []
        def handler(request):
            requests.append(request)
            if request.url.path.endswith('/models'):
                return httpx.Response(200, json={'data': [{'id': 'docker.io/ai/ministral3:8B-Q4_K_M'}]})
            return httpx.Response(200, json={'choices': [{'message': {'content': 'Answer'}}]})
        provider = DockerModelRunner('http://local/engines/v1', 'ministral3:8B-Q4_K_M', 2)
        await provider.client.aclose()
        provider.client = httpx.AsyncClient(base_url='http://local/engines/v1/', transport=httpx.MockTransport(handler))
        try:
            self.assertEqual(await provider.chat('system', 'question', max_tokens=10), 'Answer')
            self.assertEqual([r.url.path for r in requests], ['/engines/v1/models', '/engines/v1/chat/completions'])
            self.assertEqual(json.loads(requests[-1].content)['model'], 'docker.io/ai/ministral3:8B-Q4_K_M')
        finally:
            await provider.close()


class ContractTests(unittest.TestCase):
    def test_blank_history_invalid(self):
        with self.assertRaises(ValidationError):
            ChatRequest(message='hi', history=[{'role': 'user', 'content': '  '}])

    def test_context_excerpt_is_exact_and_missing_cvss_not_required(self):
        source = Source(id='a', source='nvd', document_excerpt='x' * 2000, metadata={})
        selected, chunks, generic = select_context([source], 'What is CVE-2023-27849?', ['CVE-2023-27849'], 500)
        self.assertLessEqual(len('\n\n'.join(chunks)), 500)
        self.assertTrue(chunks[0].endswith(selected[0].document_excerpt))
        self.assertLess(len(selected[0].document_excerpt), 2000)
        system, _ = build_prompt('en', 'question', 'question', chunks, generic)
        self.assertIn('only if present', system)
        self.assertNotIn('exactly two', system)

    def test_markdown_cvss_version_is_not_mistaken_for_score(self):
        from app.services.answer_validation import validate_answer
        source = Source(id='a', document_excerpt='A vulnerability.', metadata={'base_score': 9.8, 'cvss_version': '3.1'})
        self.assertIsNone(validate_answer('CRÍTICA (CVSS 3.1: **9.8**) [1].', [source]))
        self.assertEqual(validate_answer('CVSS 3.1: **10.0** [1].', [source]), 'unsupported_numbers')
        self.assertIsNone(validate_answer('CVSS 3.1, score 9.8 [1].', [source]))
        self.assertIsNone(validate_answer('CVSS v3.1 [1].', [source]))
        self.assertEqual(validate_answer('CVSS 9.0 [1].', [source]), 'unsupported_numbers')
        other = Source(id='b', document_excerpt='Record.', metadata={'base_score': 9.8})
        score_only = Source(id='c', document_excerpt='Record.', metadata={'base_score': 3.1})
        self.assertEqual(validate_answer('CVSS 3.1 [2].', [score_only, other]), 'unsupported_numbers')

    def test_capec_and_cwe_ids_are_normalized_only_from_matching_metadata(self):
        from app.services.answer_validation import supported_identifiers, validate_answer
        capec = Source(id='capec', source='capec', cve_id='CVE-2022-29494',
            document_excerpt='Buffer overflow via environment variables.',
            metadata={'content_type': 'capec', 'entity_id': '10'})
        cwe = Source(id='cwe', source='cwe', cve_id='CVE-2022-29494',
            document_excerpt='Input validation weakness.',
            metadata={'content_type': 'cwe', 'entity_id': 'CWE-20'})
        spoofed = Source(id='other', source='nvd', cve_id='CVE-2022-29494',
            document_excerpt='Generic record.', metadata={'content_type': 'nvd', 'entity_id': '10'})
        sources = [capec, cwe, spoofed]
        self.assertEqual(supported_identifiers(sources),
            {'CVE-2022-29494', 'CAPEC-10', 'CWE-20'})
        self.assertIsNone(validate_answer('CAPEC-10 describes the related pattern [1].', [capec]))
        self.assertIsNone(validate_answer('CWE-20 is related [1].', [cwe]))
        self.assertEqual(validate_answer('CAPEC-10 is related [1].', [spoofed]),
                         'unsupported_identifiers')
        self.assertEqual(validate_answer('CAPEC-999 is related [1].', [capec]),
                         'unsupported_identifiers')

    def test_context_includes_canonical_related_ids(self):
        source = Source(id='capec', source='capec', cve_id='CVE-2022-29494',
            document_excerpt='Buffer overflow.', metadata={'content_type': 'capec', 'entity_id': '10'})
        _, chunks, _ = select_context([source], 'attack pattern CVE-2022-29494',
                                     ['CVE-2022-29494'], 500)
        self.assertIn('related_ids=CAPEC-10,CVE-2022-29494', chunks[0])

    def test_compound_question_keeps_complementary_evidence(self):
        sources = [Source(id=k, source=k, document_excerpt='Evidence', metadata={}) for k in ('nvd', 'cwe')]
        selected, _, _ = select_context(sources, 'What is CVE-2023-27849 and how can it be mitigated?', ['CVE-2023-27849'], 12000)
        self.assertEqual(len(selected), 2)

    def test_health_separates_server_and_missing_collection_and_validation_ids(self):
        from app.main import app
        with TestClient(app) as client:
            service = app.state.service
            service.repository = Mock()
            service.repository.check.side_effect = AppError('collection_missing', 'Missing')
            service.embeddings = Mock()
            async def available(): return True
            service.llm.check = available
            response = client.get('/api/health')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()['chroma'], 'available')
            self.assertEqual(response.json()['collection_status'], 'unavailable')
            response = client.post('/api/chat', json={'message': ' '})
            self.assertEqual(response.status_code, 422)
            self.assertEqual(response.headers['x-request-id'], response.json()['request_id'])

    def test_repository_missing_and_incompatible_collections(self):
        from chromadb.errors import NotFoundError
        repository = ChromaRepository(Settings())
        repository.client = Mock()
        repository.client.get_collection.side_effect = NotFoundError('missing')
        with self.assertRaises(AppError) as caught: repository.check()
        self.assertEqual(caught.exception.code, 'collection_missing')
        repository.client.get_collection.side_effect = None
        repository.client.get_collection.return_value.metadata = {'dimension': 768}
        with self.assertRaises(AppError) as caught: repository.check()
        self.assertEqual(caught.exception.code, 'collection_incompatible')

class TimeoutTests(unittest.IsolatedAsyncioTestCase):
    async def test_retrieval_timeout_and_generation_failure_are_logged(self):
        import time
        repository = Repository()
        repository.search = lambda *args: (time.sleep(0.03) or [])
        service = ChatService(Settings(chroma_timeout=0.001), Preparer(), Embeddings(), repository, LLM())
        with self.assertLogs('cve.retrieval') as logs:
            with self.assertRaises(AppError) as caught:
                await service.run(ChatRequest(message='Test'))
        self.assertEqual(caught.exception.status, 504)
        self.assertIn('retrieval_failed', [r.msg for r in logs.records])
        service = ChatService(Settings(), Preparer(), Embeddings(), Repository(), SequenceLLM([]))
        with self.assertLogs('cve.retrieval') as logs:
            with self.assertRaises(RuntimeError):
                await service.run(ChatRequest(message='Test'))
        self.assertIn('generation_failed', [r.msg for r in logs.records])

    async def test_llm_timeout_returns_504(self):
        def fail(request): raise httpx.ReadTimeout('timed out', request=request)
        llm = DockerModelRunner('http://local/engines/v1', 'ministral3:8B-Q4_K_M', 1)
        await llm.client.aclose()
        llm.resolved_model = 'docker.io/ai/ministral3:8B-Q4_K_M'
        llm._resolved_until = float('inf')
        llm.client = httpx.AsyncClient(base_url='http://local/engines/v1/', transport=httpx.MockTransport(fail))
        try:
            with self.assertRaises(AppError) as caught: await llm.chat('system', 'question', max_tokens=1)
            self.assertEqual(caught.exception.status, 504)
        finally: await llm.close()

    def test_transport_timeout_is_set_before_any_network_call(self):
        from app.adapters.bounded_chroma import BoundedHttpClient
        client = BoundedHttpClient('localhost', 18001, 'default_tenant', 'default_database', 0.3)
        try: self.assertEqual(client.api._session.timeout.read, 0.3)
        finally: client.close()

    def test_embedding_rejects_long_input_before_model_truncation(self):
        from app.adapters.embeddings import OnnxEmbeddings
        embedder = OnnxEmbeddings('unused')
        embedder._checked = True
        embedder.tokenizer = Mock()
        embedder.tokenizer.encode.return_value.ids = list(range(257))
        with self.assertRaises(AppError) as caught: embedder.embed('word ' * 300)
        self.assertEqual(caught.exception.code, 'query_too_long')
