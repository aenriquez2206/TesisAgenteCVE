"""Read-only latency sampling: first request, prepared services, and two users.

PYTHONPATH=backend .venv/bin/python backend/tests/benchmark_latency.py --api http://localhost:8000
No runtime configuration changes or collection writes are made by this script.
"""
import argparse
import asyncio
import json
import time
from pathlib import Path

import httpx
from evaluate_agent import latency_summary


def questions(cve, other):
    return [f'¿Cuál es el CVSS de {cve}?', f'¿Qué es {cve}?',
            f'Explicame el patron de ataque asociado a {cve}',
            f'¿Qué productos están afectados por {cve}?',
            f'¿Qué mitigación específica documenta {cve}?',
            f'Compara {cve} y {other}: descripción, severidad y diferencias.']


async def sample(client, question, label):
    started = time.monotonic()
    record = {'query': question, 'sample': label}
    try:
        response = await client.post('/api/chat', json={'message': question})
        body = response.json()
        record.update(status_code=response.status_code, trace=body.get('trace'),
                      answer=body.get('answer'), sources=body.get('sources'), error=body.get('code'))
    except (httpx.HTTPError, ValueError) as exc:
        record.update(status_code=None, error=type(exc).__name__)
    record['duration_ms'] = round((time.monotonic() - started) * 1000)
    print(label, record['status_code'], record['duration_ms'], flush=True)
    return record


async def run(args):
    queries = questions(args.cve, args.other)
    report = {'api': args.api, 'repeats': args.repeats, 'first_request': [], 'warm': [], 'two_users': []}
    output = Path(args.output)
    def save():
        report['latency'] = {phase: latency_summary(report[phase]) for phase in ('first_request', 'warm', 'two_users')}
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    async with httpx.AsyncClient(base_url=args.api, timeout=600) as client:
        report['first_request'].append(await sample(client, queries[1], 'first_request'))
        save()
        for iteration in range(args.repeats):
            for index, query in enumerate(queries):
                report['warm'].append(await sample(client, query, f'warm-{iteration}-{index}'))
                save()
        for iteration in range(args.repeats):
            results = await asyncio.gather(*(sample(client, query, f'two-users-{iteration}-{index}')
                                             for index, query in enumerate(queries[1:3])))
            report['two_users'].extend(results)
            save()
    # First request is not called a cold model measurement: the runner may have
    # been loaded by another client. Record the runtime configuration separately.
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--api', default='http://localhost:8000')
    parser.add_argument('--cve', default='CVE-2022-29494')
    parser.add_argument('--other', default='CVE-2023-27849')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--output', default='/tmp/cve-latency-samples.json')
    args = parser.parse_args()
    if args.repeats < 1: parser.error('--repeats must be positive')
    asyncio.run(run(args))


if __name__ == '__main__':
    main()
