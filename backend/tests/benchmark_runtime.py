"""Measure a manually configured Model Runner with a fixed token budget.

Run serially, with no active agent evaluation. This script does not configure or
unload models. Truncated raw benchmark output is recorded, never served by /chat.
"""
import argparse
import json
import time
from pathlib import Path

import httpx


def run(args):
    samples = []
    with httpx.Client(timeout=180) as client:
        for iteration in range(args.repeats):
            started = time.monotonic()
            response = client.post(args.url.rstrip('/') + '/chat/completions', json={
                'model': args.model,
                'messages': [{'role': 'user', 'content': 'Describe en español, en aproximadamente 30 palabras, la diferencia entre los identificadores CVE y CWE.'}],
                'max_tokens': 60, 'stream': False, 'temperature': .1})
            body = response.json()
            samples.append({'iteration': iteration, 'duration_ms': round((time.monotonic()-started)*1000),
                'status': response.status_code, 'usage': body.get('usage'), 'timings': body.get('timings'),
                'choices': body.get('choices'), 'error': body.get('error')})
            Path(args.output).write_text(json.dumps(samples, ensure_ascii=False, indent=2)+'\n')
            print(iteration, samples[-1]['duration_ms'], body.get('timings'), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', default='http://localhost:12434/engines/v1')
    parser.add_argument('--model', default='docker.io/ai/ministral3:8B-Q4_K_M')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--output', default='/tmp/cve-runtime-samples.json')
    args = parser.parse_args()
    if args.repeats < 1: parser.error('--repeats must be positive')
    run(args)
