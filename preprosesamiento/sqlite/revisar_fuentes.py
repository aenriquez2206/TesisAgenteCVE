"""Audita los cinco archivos provistos sin modificarlos ni insertar registros.

Emite JSON a stdout; no requiere paquetes externos ni acceso a la red.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

SOURCE = Path(__file__).resolve().parent / 'fuentes'
CVE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE | re.ASCII)
CWE_FIELDS = ['Name', 'Description', 'Extended Description', 'Potential Mitigations']


def read_csv(name: str) -> tuple[list[dict], dict]:
    path = SOURCE / name
    content = path.read_bytes()
    with path.open(encoding='utf-8-sig', newline='') as file:
        reader = csv.DictReader(file)
        records = list(reader)
        headers = reader.fieldnames
    malformed = []
    extra_empty = 0
    for number, record in enumerate(records, start=1):
        extra = record.get(None)
        if extra == ['']:
            extra_empty += 1
        elif extra is not None:
            malformed.append({'record': number, 'extra_values': extra})
        missing = [k for k, value in record.items() if k is not None and value is None]
        if missing:
            malformed.append({'record': number, 'missing_columns': missing})
    metadata = {
        'file': name, 'bytes': len(content),
        'sha256': hashlib.sha256(content).hexdigest(),
        'encoding': 'UTF-8', 'bom': content.startswith(b'\xef\xbb\xbf'),
        'headers': headers, 'rows': len(records),
        'extra_empty_column_rows': extra_empty, 'malformed_records': malformed,
        'invalid_numeric_id_records': [
            {'record': number, 'value': record[headers[0]]}
            for number, record in enumerate(records, start=1)
            if not (record[headers[0]].isascii() and record[headers[0]].isdigit()
                    and int(record[headers[0]]) > 0)
        ],
    }
    return records, metadata


def empty_counts(records: list[dict], fields: list[str]) -> dict:
    return {field: sum(not record[field].strip() for record in records) for field in fields}


def cpe_matches(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == 'cpeMatch' and isinstance(child, list):
                yield from child
            else:
                yield from cpe_matches(child)
    elif isinstance(value, list):
        for child in value:
            yield from cpe_matches(child)


def review() -> dict:
    files = {}
    data = {}
    for name in ['capec.csv', 'cwe_hardware.csv', 'cwe_software.csv', 'files_exploits.csv']:
        data[name], files[name] = read_csv(name)
    hardware = {r['CWE-ID']: r for r in data['cwe_hardware.csv']}
    software = {r['CWE-ID']: r for r in data['cwe_software.csv']}
    shared = sorted(hardware.keys() & software.keys(), key=int)
    conflicts = {
        key: [field for field in CWE_FIELDS if hardware[key][field] != software[key][field]]
        for key in shared
        if any(hardware[key][field] != software[key][field] for field in CWE_FIELDS)
    }
    combined = hardware | software
    cwe = {
        'hardware_rows': len(data['cwe_hardware.csv']),
        'software_rows': len(data['cwe_software.csv']),
        'overlap_ids': shared, 'unique_ids': len(combined),
        'selected_field_conflicts': conflicts,
        'hardware_empty_fields': empty_counts(data['cwe_hardware.csv'], CWE_FIELDS),
        'software_empty_fields': empty_counts(data['cwe_software.csv'], CWE_FIELDS),
        'unique_empty_fields': empty_counts(list(combined.values()), CWE_FIELDS),
        'duplicate_ids_per_file': {
            name: {key: count for key, count in Counter(r['CWE-ID'] for r in data[name]).items() if count > 1}
            for name in ['cwe_hardware.csv', 'cwe_software.csv']
        },
    }
    patterns = data['capec.csv']
    pairs = [
        (int(r["'ID"]), token)
        for r in patterns for token in r['Related Weaknesses'].split('::') if token
    ]
    missing = sorted({cwe_id for _, cwe_id in pairs} - combined.keys(), key=int)
    capec = {
        'rows': len(patterns), 'unique_ids': len({r["'ID"] for r in patterns}),
        'empty_fields': empty_counts(patterns, ['Name', 'Description', 'Execution Flow', 'Prerequisites', 'Consequences', 'Related Weaknesses']),
        'relations': len(pairs), 'unique_relations': len(set(pairs)),
        'duplicate_relations': [
            {'capec_id': pattern, 'cwe_id': f'CWE-{weakness}', 'occurrences': count}
            for (pattern, weakness), count in Counter(pairs).items() if count > 1
        ],
        'referenced_cwe_count': len({key for _, key in pairs}),
        'missing_cwe_ids': [f'CWE-{key}' for key in missing],
        'relations_to_missing_cwe': sum(key not in combined for _, key in pairs),
        'unique_relations_to_missing_cwe': sum(key not in combined for _, key in set(pairs)),
    }
    exploits = data['files_exploits.csv']
    groups = defaultdict(list)
    strict_links, detected_links = set(), set()
    malformed_codes = []
    no_cve_rows, multiple_cve_rows = 0, 0
    for r in exploits:
        groups[r['id']].append(r)
        strict_codes = set()
        for token in r['codes'].split(';'):
            stripped = token.strip()
            if CVE.fullmatch(stripped):
                strict_codes.add(stripped.upper())
            if 'CVE' in token.upper() and not CVE.fullmatch(token):
                malformed_codes.append({
                    'exploit_id': int(r['id']), 'raw_token': token,
                    'valid_after_trim': bool(CVE.fullmatch(stripped)),
                })
        strict_links.update((r['id'], code) for code in strict_codes)
        detected_links.update((r['id'], code.upper()) for code in CVE.findall(r['codes']))
        no_cve_rows += not strict_codes
        multiple_cve_rows += len(strict_codes) > 1
    duplicates = {key: len(values) for key, values in groups.items() if len(values) > 1}
    exploit = {
        'rows': len(exploits), 'unique_ids': len(groups),
        'duplicate_id_count': len(duplicates), 'extra_rows': len(exploits) - len(groups),
        'duplicate_ids': duplicates,
        'description_conflict_ids': [key for key, values in groups.items() if len({r['description'] for r in values}) > 1],
        'codes_conflict_ids': [key for key, values in groups.items() if len({r['codes'] for r in values}) > 1],
        'empty_codes_rows': sum(not r['codes'].strip() for r in exploits),
        'rows_without_strict_cve': no_cve_rows, 'multi_cve_rows': multiple_cve_rows,
        'strict_unique_links': len(strict_links), 'strict_unique_cve': len({code for _, code in strict_links}),
        'regex_detected_unique_links': len(detected_links),
        'regex_detected_unique_cve': len({code for _, code in detected_links}),
        'malformed_cve_tokens': malformed_codes,
    }
    content = (SOURCE / 'NVDExample.json').read_bytes()
    payload = json.loads(content)
    files['NVDExample.json'] = {
        'file': 'NVDExample.json', 'bytes': len(content),
        'sha256': hashlib.sha256(content).hexdigest(),
        'encoding': 'UTF-8', 'root_keys': list(payload),
        'rows': len(payload['vulnerabilities']),
    }
    summaries = []
    nvd_weaknesses = set()
    for wrapper in payload['vulnerabilities']:
        c = wrapper['cve']
        weaknesses = sorted({
            d['value'] for group in c.get('weaknesses', []) for d in group['description']
        })
        nvd_weaknesses.update(weaknesses)
        matches = list(cpe_matches(c.get('configurations', [])))
        summaries.append({
            'id': c['id'], 'published': c['published'], 'last_modified': c['lastModified'],
            'status': c['vulnStatus'], 'description_languages': [d['lang'] for d in c['descriptions']],
            'metrics': [{
                'family': family, 'version': entry['cvssData']['version'],
                'source': entry.get('source'), 'type': entry.get('type'),
                'base_score': entry['cvssData']['baseScore'],
                'attack_vector': entry['cvssData'].get('attackVector', entry['cvssData'].get('accessVector')),
            } for family, entries in c['metrics'].items() for entry in entries],
            'weakness_ids': weaknesses,
            'missing_cwe_ids': [key for key in weaknesses if key.startswith('CWE-') and key[4:] not in combined],
            'cpe_matches': len(matches),
            'references': len(c['references']), 'unique_reference_urls': len({r['url'] for r in c['references']}),
            'exploit_ids': sorted({int(key) for key, code in strict_links if code == c['id']}),
            'published_in_2023_2026': '2023-01-01' <= c['published'] < '2027-01-01',
        })
    missing_all = {f'CWE-{key}' for key in missing} | {
        key for key in nvd_weaknesses if key.startswith('CWE-') and key[4:] not in combined
    }
    return {
        'files': files, 'cwe': cwe, 'capec': capec, 'exploit_db': exploit,
        'nvd': {'rows': len(summaries), 'unique_ids': len({c['id'] for c in summaries}), 'records': summaries},
        'coverage': {
            'missing_cwe_ids': sorted(missing_all, key=lambda key: int(key[4:])),
            'cwe_ids_after_future_placeholder_load': len(combined) + len(missing_all),
            'cve_exploit_matches': sum(len(c['exploit_ids']) for c in summaries),
        },
    }


if __name__ == '__main__':
    print(json.dumps(review(), ensure_ascii=False, indent=2))
