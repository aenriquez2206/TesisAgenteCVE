"""Compare context selection budgets using identical read-only retrieval results.

This isolates evidence coverage; it does not certify generated answer semantics.
"""
import argparse
import json
from pathlib import Path

from app.adapters.chroma_repository import ChromaRepository
from app.adapters.embeddings import OnnxEmbeddings
from app.config import Settings
from app.services.query_preparer import CVE
from app.services.query_intent import fast_intent, requested_kinds, QUERIES
from app.services.prompt_builder import select_context
from evaluate_agent import collection_inventory, build_cases


def run(output):
    settings = Settings.from_env()
    repository = ChromaRepository(settings)
    embeddings = OnnxEmbeddings(settings.embedding_hash, settings.embedding_tokenizer_hash)
    report = {'kind': 'retrieval_and_context_only', 'cases': [], 'budgets': {str(n): {} for n in (6000, 12000)}}
    try:
        collection = repository._collection()
        before = (collection.count(), collection.metadata, collection.configuration)
        cases = build_cases(collection_inventory(repository))
        for case in cases:
            message = case['query']
            cves = list(dict.fromkeys(x.upper() for x in CVE.findall(message)))
            if not cves and len(case['expected_cve_ids']) == 1:
                cves = case['expected_cve_ids']
                resolved = message.rstrip('?. ') + ' ' + cves[0]
            else:
                resolved = message
            intent = fast_intent(resolved)
            kinds = requested_kinds(message, intent)
            if intent and len(cves) == 1:
                query = QUERIES[intent].format(cve=cves[0])
            else:
                # Canonical topic query isolates budget effects without spending
                # LLM calls on translation. Live evaluation tests actual preparation.
                query = ' '.join(cves + list(kinds))
            sources = {}
            if cves:
                if intent not in ('description', 'cvss'):
                    for source in repository.search(embeddings.embed(query), settings.top_k, cves):
                        sources[source.id] = source
                for cve in cves:
                    for source in repository.grouped(cve, kinds):
                        sources.setdefault(source.id, source)
            record = {'case_id': case['case_id'], 'supported': case['supported'], 'query': message,
                      'canonical_query_en': query, 'budgets': {}}
            for budget in (6000, 12000):
                selected, chunks, _ = select_context(list(sources.values()), message, cves, budget, intent=intent)
                used_cves = {source.cve_id for source in selected}
                used_types = {source.source for source in selected}
                match = (set(case['expected_cve_ids']).issubset(used_cves)
                         and set(case['expected_source_types']).issubset(used_types)
                         and not (set(case['expected_absent_source_types']) & used_types))
                if case['expected_status'] == 422:
                    match = not sources
                if case.get('expect_no_evidence'):
                    match = not selected
                record['budgets'][str(budget)] = {'evidence_match': match, 'source_ids': [s.id for s in selected],
                                                'context_chars': len('\n\n'.join(chunks))}
            report['cases'].append(record)
        for budget in report['budgets']:
            supported = [case for case in report['cases'] if case['supported']]
            report['budgets'][budget] = {'supported_cases': len(supported),
                'evidence_matches': sum(case['budgets'][budget]['evidence_match'] for case in supported),
                'evidence_match_rate': round(sum(case['budgets'][budget]['evidence_match'] for case in supported) / len(supported), 3)}
        refreshed = repository._collection(refresh=True)
        report['collection_metadata_count_unchanged'] = before == (refreshed.count(), refreshed.metadata, refreshed.configuration)
        Path(output).write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps(report['budgets']), flush=True)
    finally:
        repository.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='/tmp/cve-context-budgets.json')
    run(parser.parse_args().output)
