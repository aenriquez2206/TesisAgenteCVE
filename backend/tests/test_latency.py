import asyncio
import json
import threading
import time
import unittest
from unittest.mock import Mock

import httpx
from app.adapters.chroma_repository import ChromaRepository
from app.adapters.model_runner import DockerModelRunner
from app.config import Settings
from app.contracts import ChatRequest, HistoryMessage, Source
from app.errors import AppError
from app.services.chat import ChatService
from app.services.query_preparer import LocalQueryPreparer
from app.services.prompt_builder import select_context
from test_chat import Embeddings, Repository
from test_reliability import SequenceLLM

CVE = 'CVE-2023-27849'


def nvd(cve=CVE, **metadata):
    return Source(id=cve + ':nvd', source='nvd', cve_id=cve,
                  document_excerpt='Remote code execution.',
                  metadata={'cve_id': cve, 'content_type': 'nvd', **metadata})


class FastRepository(Repository):
    def __init__(self, sources=None):
        super().__init__()
        self.sources = [nvd(base_score=9.8, severity='CRITICAL', cvss_version='3.1')] if sources is None else sources
        self.groups = []

    def grouped(self, cve_id, kinds):
        self.groups.append((cve_id, kinds))
        return [s for s in self.sources if s.cve_id == cve_id and s.source in kinds]


class FastPathTests(unittest.IsolatedAsyncioTestCase):
    def test_numeric_grounding_accepts_version_prefix_without_allowing_other_versions(self):
        from app.services.answer_validation import validate_answer
        source = nvd().model_copy(update={'document_excerpt': 'Package v1.0.0 permits remote code execution.'})
        self.assertIsNone(validate_answer('Package version 1.0.0 permits remote code execution [1].', [source]))
        self.assertEqual(validate_answer('Package version 1.0.1 permits remote code execution [1].', [source]),
                         'unsupported_numbers')

    async def test_completed_request_stops_watcher_even_if_receive_swallows_cancel(self):
        from types import SimpleNamespace
        from app.api.routes import chat
        polls = 0
        async def run(*args):
            return 'complete'
        async def receive():
            nonlocal polls
            polls += 1
            if polls == 1:
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    return {'type': 'http.request', 'body': b'', 'more_body': False}
            return {'type': 'http.disconnect'}
        request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(service=SimpleNamespace(run=run))),
                                  state=SimpleNamespace(request_id='r'), receive=receive)
        self.assertEqual(await asyncio.wait_for(chat(ChatRequest(message='hi'), request), 1), 'complete')
        self.assertEqual(polls, 1)

    async def test_disconnected_client_cancels_generation(self):
        from types import SimpleNamespace
        from app.api.routes import chat
        began, canceled = asyncio.Event(), asyncio.Event()
        async def run(*args):
            began.set()
            try:
                await asyncio.Event().wait()
            finally:
                canceled.set()
        async def receive():
            await began.wait()
            return {'type': 'http.disconnect'}
        request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(service=SimpleNamespace(run=run))),
                                  state=SimpleNamespace(request_id='r'), receive=receive)
        with self.assertRaises(AppError) as error:
            await chat(ChatRequest(message='hi'), request)
        self.assertEqual(error.exception.code, 'client_disconnected')
        self.assertTrue(canceled.is_set())

    async def test_exact_cvss_has_no_model_or_embedding_calls_and_valid_citation(self):
        llm, embeddings, repository = SequenceLLM([]), Mock(), FastRepository()
        service = ChatService(Settings(), LocalQueryPreparer(llm), embeddings, repository, llm)
        for question in [f'¿Cuál es el CVSS de {CVE}?', f'What is the CVSS score for {CVE}?']:
            result = await service.run(ChatRequest(message=question))
            self.assertIn('9.8', result.answer)
            self.assertIn('[1]', result.answer)
            self.assertTrue(result.trace.template_answer)
            self.assertEqual(result.trace.llm_calls, 0)
            self.assertEqual(result.trace.timings_ms['embedding'], 0)
            self.assertEqual(result.trace.generation_status, 'skipped')
            self.assertEqual(result.trace.retrieval_method, 'cve_metadata')
        embeddings.embed.assert_not_called()
        self.assertEqual(repository.calls, [])
        self.assertEqual(llm.calls, [])

    async def test_missing_values_are_explicit_and_wrong_cve_is_not_used(self):
        llm = SequenceLLM([])
        repository = FastRepository([nvd()])
        service = ChatService(Settings(), LocalQueryPreparer(llm), Mock(), repository, llm)
        result = await service.run(ChatRequest(message=f'¿Qué puntuación CVSS tiene {CVE}?'))
        self.assertIn('puntuación CVSS no registrada', result.answer)
        self.assertIn('severidad no registrada', result.answer)
        self.assertNotIn('0.0', result.answer)
        result = await service.run(ChatRequest(message='¿Cuál es el CVSS de CVE-2099-9999999?'))
        self.assertEqual(result.sources, [])
        self.assertFalse(result.trace.template_answer)
        self.assertEqual(result.trace.llm_calls, 0)

    async def test_description_only_generates_once_and_does_not_embed(self):
        llm, embeddings = SequenceLLM(['Ejecución remota de código [1].']), Mock()
        service = ChatService(Settings(), LocalQueryPreparer(llm), embeddings, FastRepository(), llm)
        result = await service.run(ChatRequest(message=f'¿Qué es {CVE}?'))
        embeddings.embed.assert_not_called()
        self.assertEqual(result.trace.llm_calls, 1)
        self.assertEqual(result.trace.translation_status, 'templated')

    async def test_truncated_generation_retries_once_without_publishing_partial_text(self):
        class TruncatedLLM(SequenceLLM):
            def __init__(self):
                super().__init__([])
                self.budgets = []
            async def chat(self, system, user, *, max_tokens):
                self.budgets.append(max_tokens)
                if len(self.budgets) == 1:
                    raise AppError('llm_truncated', 'partial', 502)
                return 'Ejecución remota de código [1].'
        llm = TruncatedLLM()
        result = await ChatService(Settings(), LocalQueryPreparer(llm), Mock(), FastRepository(), llm).run(
            ChatRequest(message=f'¿Qué es {CVE}?'))
        self.assertEqual(llm.budgets, [220, 350])
        self.assertEqual(result.trace.retries, 1)
        self.assertEqual(result.trace.llm_calls, 2)
        self.assertNotIn('partial', result.answer)

    async def test_unambiguous_followup_and_multiple_cves(self):
        llm = SequenceLLM([])
        preparer = LocalQueryPreparer(llm)
        result = await preparer.prepare('¿Y cómo se mitiga?', [HistoryMessage(role='user', content=f'¿Qué es {CVE}?')])
        self.assertEqual(result.intent, 'mitigation')
        self.assertIn(CVE, result.query_en)
        self.assertEqual(result.llm_calls, 0)
        with self.assertRaises(AppError) as error:
            await preparer.prepare('How is it mitigated?', [HistoryMessage(role='user', content=f'Compare {CVE} and CVE-2024-3094')])
        self.assertEqual(error.exception.code, 'clarification_required')
        self.assertEqual(llm.calls, [])
        with self.assertRaises(AppError) as error:
            await preparer.prepare('¿A cuál se refiere?', [HistoryMessage(role='user', content=f'Compara {CVE} y CVE-2024-3094')])
        self.assertEqual(error.exception.code, 'clarification_required')

    async def test_missing_record_question_does_not_invent_a_weakness(self):
        llm, repository = SequenceLLM([]), FastRepository()
        service = ChatService(Settings(), LocalQueryPreparer(llm), Embeddings(), repository, llm)
        result = await service.run(ChatRequest(message=f'¿La colección registra una debilidad CWE para {CVE}?'))
        self.assertIn('No se recuperaron registros CWE', result.answer)
        self.assertIn('[1]', result.answer)
        self.assertTrue(result.trace.template_answer)
        self.assertEqual(result.trace.llm_calls, 0)

    async def test_extra_constraints_use_model_and_keep_versions(self):
        query = f'What is the risk of {CVE} in OpenSSL 1.2.3?'
        llm = SequenceLLM([json.dumps({'language': 'es', 'query_en': query})])
        result = await LocalQueryPreparer(llm).prepare(f'¿Cuál es el riesgo de {CVE} en OpenSSL 1.2.3?', [])
        self.assertIsNone(result.intent)
        self.assertEqual(result.query_en, query)
        self.assertEqual(result.llm_calls, 1)

    async def test_comparison_fetches_missing_top_k_member(self):
        other = 'CVE-2024-3094'
        repository = FastRepository([nvd(), nvd(other)])
        llm = SequenceLLM([f'Compare {CVE} and {other}', f'{CVE} [1]. {other} [2].'])
        # English standalone needs no preparer model call.
        llm = SequenceLLM([f'{CVE} [1]. {other} [2].'])
        result = await ChatService(Settings(context_chars=1000), LocalQueryPreparer(llm),
            Embeddings(), repository, llm).run(ChatRequest(message=f'Compare {CVE} and {other}'))
        self.assertEqual({s.cve_id for s in result.sources}, {CVE, other})
        self.assertEqual({cve for cve, _ in repository.groups}, {CVE, other})
        self.assertEqual(result.trace.llm_calls, 1)

    async def test_comparison_appends_cited_scores_from_each_nvd_record(self):
        other = 'CVE-2024-3094'
        repository = FastRepository([nvd(base_score=9.8, severity='CRITICAL'),
                                     nvd(other, base_score=7.5, severity='HIGH')])
        llm = SequenceLLM([f'{CVE} permits remote code execution [1]. {other} also permits remote code execution [2].'])
        result = await ChatService(Settings(), LocalQueryPreparer(llm), Embeddings(), repository, llm).run(
            ChatRequest(message=f'Compare {CVE} and {other}'))
        self.assertIn('9.8', result.answer)
        self.assertIn('7.5', result.answer)
        self.assertIn('[1]', result.answer)
        self.assertIn('[2]', result.answer)
        self.assertNotIn('score=9.8', llm.calls[0][1])
        self.assertNotIn('score=7.5', llm.calls[0][1])
        self.assertEqual(result.trace.llm_calls, 1)

    async def test_timeout_does_not_release_active_retrieval_permits(self):
        active, peak = 0, 0
        lock = threading.Lock()
        def slow():
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(.06)
            with lock:
                active -= 1
            return []
        service = ChatService(Settings(chroma_timeout=.01), Mock(), Mock(), FastRepository(), SequenceLLM([]))
        results = await asyncio.gather(*(service._retrieval('test', {}, 'q', 1, slow) for _ in range(12)), return_exceptions=True)
        self.assertTrue(all(isinstance(result, AppError) for result in results))
        await asyncio.sleep(.1)
        self.assertEqual(peak, 4)
        self.assertEqual(active, 0)


class CollectionCacheTests(unittest.TestCase):
    def test_successful_chat_returns_through_real_middleware(self):
        from fastapi.testclient import TestClient
        from app.main import app
        from test_chat import Preparer, LLM
        with TestClient(app) as client:
            app.state.service = ChatService(Settings(), Preparer(), Embeddings(), Repository(), LLM())
            response = client.post('/api/chat', json={'message': f'What is {CVE}?'})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()['answer'], 'Remote code execution [1].')
            self.assertEqual(response.headers['x-request-id'], response.json()['request_id'])

    def repository(self):
        repository = ChromaRepository(Settings())
        repository.client = Mock()
        collection = repository.client.get_collection.return_value
        collection.metadata = {'status': 'validated', 'dimension': 384,
                               'embedding_model': repository.settings.embedding_model}
        collection.configuration = {'hnsw': {'space': 'cosine'}}
        collection.query.return_value = {'ids': [[]], 'documents': [[]], 'metadatas': [[]], 'distances': [[]]}
        return repository, collection

    def test_cache_refresh_health_and_failure_invalidation(self):
        repository, collection = self.repository()
        repository.search([0.] * 384, 8, [])
        repository.search([0.] * 384, 8, [])
        self.assertEqual(repository.client.get_collection.call_count, 1)
        collection.count.assert_not_called()
        repository.check()
        self.assertEqual(repository.client.get_collection.call_count, 2)
        collection.count.assert_called_once()
        repository._validated_until = 0
        repository.search([0.] * 384, 8, [])
        self.assertEqual(repository.client.get_collection.call_count, 3)
        collection.query.side_effect = RuntimeError('down')
        with self.assertRaises(AppError): repository.search([0.] * 384, 8, [])
        self.assertIsNone(repository._cached_collection)

    def test_refresh_is_synchronized(self):
        from concurrent.futures import ThreadPoolExecutor
        repository, _ = self.repository()
        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(lambda _: repository._collection(), range(12)))
        self.assertEqual(repository.client.get_collection.call_count, 1)

    def test_grouped_pagination_preserves_per_kind_limit(self):
        repository, collection = self.repository()
        def page(kinds):
            return {'ids': [f'{kind}-{i}' for i, kind in enumerate(kinds)],
                    'documents': ['text'] * len(kinds),
                    'metadatas': [{'cve_id': CVE, 'content_type': kind} for kind in kinds]}
        collection.get.side_effect = [page(['capec'] * 64), page(['nvd'] * 3)]
        sources = repository.grouped(CVE, ('nvd', 'capec'))
        self.assertEqual([s.source for s in sources], ['nvd'] * 3 + ['capec'] * 3)
        self.assertEqual([call.kwargs['offset'] for call in collection.get.call_args_list], [0, 0])
        self.assertEqual(collection.get.call_args_list[1].kwargs['where']['$and'][1],
                         {'content_type': {'$in': ['nvd']}})

    def test_filter_restart_does_not_duplicate_underfilled_kind(self):
        repository, collection = self.repository()
        def page(ids, kinds):
            return {'ids': ids, 'documents': ['text'] * len(ids),
                    'metadatas': [{'cve_id': CVE, 'content_type': kind} for kind in kinds]}
        collection.get.side_effect = [page(['nvd-1'] + [f'capec-{i}' for i in range(63)], ['nvd'] + ['capec']*63),
                                      page(['nvd-1', 'nvd-2'], ['nvd', 'nvd'])]
        sources = repository.grouped(CVE, ('nvd', 'capec'))
        self.assertEqual([s.id for s in sources if s.source == 'nvd'], ['nvd-1', 'nvd-2'])
        self.assertEqual(len(sources), 5)

    def test_context_reserves_nvd_and_each_comparison_member(self):
        sources = [Source(id=f'capec-{i}', source='capec', cve_id=CVE, document_excerpt='x'*2000,
                          metadata={}) for i in range(8)] + [nvd(), nvd('CVE-2024-3094')]
        selected, chunks, _ = select_context(sources, 'Describe CAPEC', [CVE, 'CVE-2024-3094'], 1500)
        self.assertEqual({s.cve_id for s in selected}, {CVE, 'CVE-2024-3094'})
        self.assertTrue(any(s.source == 'nvd' and s.cve_id == CVE for s in selected))
        self.assertLessEqual(len('\n\n'.join(chunks)), 1500)

    def test_basic_comparison_uses_nvd_and_keeps_both_members(self):
        other = 'CVE-2024-3094'
        extra = Source(id='pattern', source='capec', cve_id=CVE, document_excerpt='x'*2000, metadata={})
        selected, _, _ = select_context([extra, nvd(), nvd(other)],
            f'Compara {CVE} y {other}: descripción, severidad y diferencias.', [CVE, other], 1000)
        self.assertEqual({s.source for s in selected}, {'nvd'})
        self.assertEqual({s.cve_id for s in selected}, {CVE, other})

    def test_pattern_name_and_definition_do_not_mix_different_entities(self):
        sources = [Source(id='name-1', source='capec', cve_id=CVE, document_excerpt='Reflected XSS',
                          metadata={'field': 'name', 'entity_id': '591'}),
                   Source(id='desc-2', source='capec', cve_id=CVE, document_excerpt='Persistently stored malicious script.',
                          metadata={'field': 'description', 'entity_id': '592'}),
                   Source(id='name-2', source='capec', cve_id=CVE, document_excerpt='Stored XSS',
                          metadata={'field': 'name', 'entity_id': '592'}), nvd()]
        selected, _, _ = select_context(sources, f'Which attack pattern is linked to {CVE}?', [CVE], 6000, intent='capec')
        self.assertEqual([s.id for s in selected], ['desc-2', 'name-2'])


class ModelCacheTests(unittest.IsolatedAsyncioTestCase):
    async def test_generations_are_serial_and_cancellation_releases_slot(self):
        began = asyncio.Event()
        active = peak = calls = 0
        async def handler(request):
            nonlocal active, peak, calls
            calls += 1
            active += 1
            peak = max(peak, active)
            try:
                if calls == 1:
                    began.set()
                    await asyncio.Event().wait()
                return httpx.Response(200, json={'choices': [{'message': {'content': 'Answer'}, 'finish_reason': 'stop'}]})
            finally:
                active -= 1
        runner = DockerModelRunner('http://local/v1', 'model', 1)
        runner._resolved_until = float('inf')
        await runner.client.aclose()
        runner.client = httpx.AsyncClient(base_url='http://local/v1/', transport=httpx.MockTransport(handler))
        first = asyncio.create_task(runner.chat('s', 'u', max_tokens=10))
        try:
            await began.wait()
            second = asyncio.create_task(runner.chat('s', 'u', max_tokens=10))
            await asyncio.sleep(.01)
            self.assertEqual(calls, 1)
            first.cancel()
            await asyncio.gather(first, return_exceptions=True)
            self.assertEqual(await asyncio.wait_for(second, .5), 'Answer')
            self.assertEqual(peak, 1)
            self.assertEqual(active, 0)
        finally:
            first.cancel()
            await runner.close()

    async def test_cache_same_id_resolution_and_error_invalidation(self):
        calls = []
        fail = False
        def handler(request):
            calls.append(request.url.path)
            if request.url.path.endswith('/models'):
                return httpx.Response(200, json={'data': [{'id': 'model'}]})
            if fail:
                return httpx.Response(500)
            return httpx.Response(200, json={'choices': [{'message': {'content': 'Answer'}, 'finish_reason': 'stop'}]})
        runner = DockerModelRunner('http://local/v1', 'model', 1)
        await runner.client.aclose()
        runner.client = httpx.AsyncClient(base_url='http://local/v1/', transport=httpx.MockTransport(handler))
        try:
            await runner.chat('s', 'u', max_tokens=10)
            await runner.chat('s', 'u', max_tokens=10)
            self.assertEqual(calls.count('/v1/models'), 1)
            fail = True
            with self.assertRaises(AppError): await runner.chat('s', 'u', max_tokens=10)
            fail = False
            await runner.chat('s', 'u', max_tokens=10)
            self.assertEqual(calls.count('/v1/models'), 2)
        finally:
            await runner.close()

    async def test_truncated_output_is_not_returned(self):
        runner = DockerModelRunner('http://local/v1', 'model', 1)
        runner._resolved_until = float('inf')
        await runner.client.aclose()
        runner.client = httpx.AsyncClient(base_url='http://local/v1/', transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={'choices': [{'message': {'content': 'partial [1]'}, 'finish_reason': 'length'}]})))
        try:
            with self.assertRaises(AppError) as error: await runner.chat('s', 'u', max_tokens=1)
            self.assertEqual(error.exception.code, 'llm_truncated')
        finally:
            await runner.close()
