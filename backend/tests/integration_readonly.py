"""Opt-in smoke test against an already running API and existing Chroma collection.

PYTHONPATH=backend CHROMA_PORT=8001 .venv/bin/python backend/tests/integration_readonly.py
Only get/query operations are used. Output goes to /tmp unless --output is provided.
"""
import argparse
import json
from pathlib import Path

import httpx

from app.adapters.chroma_repository import ChromaRepository
from app.config import Settings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--api', default='http://localhost:8000')
    parser.add_argument('--output', default='/tmp/cve-intelligence-integration.json')
    args = parser.parse_args()
    repository = ChromaRepository(Settings.from_env())
    try:
        collection = repository._collection()
        sample = collection.get(limit=10, include=['documents', 'metadatas', 'embeddings'])
        sample['embeddings'] = sample['embeddings'].tolist()
        before = {'count': collection.count(), 'metadata': collection.metadata,
                  'configuration': collection.configuration, 'sample': sample}
        questions = [
            ('¿Qué es CVE-2023-27849?', [], 'es'),
            ('What is CVE-2023-27849?', [], 'en'),
            ('¿Cómo puedo mitigar ese riesgo?', [{'role': 'user', 'content': '¿Qué es CVE-2023-27849?'}], 'es'),
            ('What is CVE-2099-9999999?', [], 'en'),
        ]
        report = {'cases': []}
        with httpx.Client(base_url=args.api, timeout=300) as client:
            health = client.get('/api/health')
            health.raise_for_status()
            report['health'] = health.json()
            for field in ('chroma', 'collection_status', 'embeddings', 'llm'):
                assert report['health'][field] == 'available', report['health']
            for question, history, language in questions:
                response = client.post('/api/chat', json={'message': question, 'history': history})
                body = response.json()
                report['cases'].append({'question': question, 'status': response.status_code, 'body': body})
                Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
                assert response.status_code == 200, body
                assert body['request_id'] == response.headers['x-request-id']
                assert body['trace']['detected_language'] == language
                assert body['trace']['model'] == 'ministral3:8B-Q4_K_M'
                if '2099' in question:
                    assert not body['sources'] and body['trace']['generation_status'] == 'skipped'
                else:
                    assert body['sources'] and body['trace']['generation_status'] == 'complete'
                if language == 'en': assert body['trace']['search_query_en'] == question
                print(question, response.status_code, body['trace']['translation_status'], flush=True)
        after_sample = collection.get(ids=sample['ids'], include=['documents', 'metadatas', 'embeddings'])
        after_sample['embeddings'] = after_sample['embeddings'].tolist()
        normalize = lambda page: {identifier: (page['documents'][i], page['metadatas'][i], page['embeddings'][i])
                                  for i, identifier in enumerate(page['ids'])}
        assert normalize(sample) == normalize(after_sample), 'Sample changed'
        refreshed = repository._collection()
        assert collection.count() == before['count']
        assert refreshed.metadata == before['metadata'] and refreshed.configuration == before['configuration']
        report['preserved'] = {'count': before['count'], 'sample_size': len(sample['ids']), 'metadata_configuration_sample_unchanged': True}
        Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
        print('Read-only integration passed; inspect the recorded answers for semantic grounding.')
    finally:
        repository.close()


if __name__ == '__main__':
    main()
