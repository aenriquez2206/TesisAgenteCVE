"""Contrato de descarga, muestreo y reemplazo; no consulta NVD real."""
import copy
import csv
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import requests

from carga_catalogo import (
    API_URL, DIRECTORY, INSERT_COLUMNS, NVDAPIError, NVDClient, PageCache, Prepared,
    Selection, annual_sample, download_and_select, eligibility, iso_date,
    load_catalogue, monthly_windows, parse_date, prepare_catalogue, read_csv,
    valid_reference,
)
from crear_base import create_database


def cve(year=2023, number=1000, **changes):
    return {
        'id': f'CVE-{year}-{number}', 'published': f'{year}-01-02T00:00:00.000Z',
        'lastModified': f'{year}-02-01T00:00:00.000Z', 'vulnStatus': 'Analyzed',
        'sourceIdentifier': 'fixture', 'descriptions': [{'lang': 'en', 'value': 'Descripción de prueba completa.'}],
        'metrics': {'cvssMetricV31': [{'cvssData': {'version': '3.1', 'attackVector': 'NETWORK', 'baseScore': 7.5}}]},
        'weaknesses': [{'description': [{'value': 'CWE-120'}, {'value': 'CWE-200'}, {'value': 'NVD-CWE-noinfo'}]}],
        'configurations': [{'nodes': [{'operator': 'OR', 'cpeMatch': [{'criteria': 'cpe:2.3:a:test:app:*:*:*:*:*:*:*:*', 'vulnerable': True}]}]}],
        'references': [{'url': 'https://vendor.example/advisory/123', 'tags': ['Vendor Advisory']}],
    } | changes


def selection(records):
    years = sorted({parse_date(r['published']).year for r in records})
    return Selection(records, {
        'cutoff': '2026-10-05T23:59:59.999Z', 'seed': 42, 'quota': 2, 'years': years,
        'annual': {str(y): {'eligible': 5, 'selected': 2, 'selected_ids': [r['id'] for r in records if parse_date(r['published']).year == y]} for y in years},
    })


class Clock:
    def __init__(self):
        self.now = 0
        self.waits = []

    def sleep(self, seconds):
        self.waits.append(seconds)
        self.now += seconds

    def monotonic(self):
        return self.now


class Response:
    def __init__(self, status=200, payload=None, headers=None):
        self.status_code = status
        self.payload = payload or {'startIndex': 0, 'totalResults': 0, 'vulnerabilities': []}
        self.headers = headers or {}

    def json(self):
        return self.payload


class Session:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.headers = {}
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        value = next(self.responses)
        if isinstance(value, Exception):
            raise value
        return value

    def close(self):
        pass


class SimulatedAPI:
    page_size = 2

    def __init__(self, fail_index=None):
        self.calls = []
        self.fail_index = fail_index
        self.progress = lambda event: None

    def page(self, start, end, index):
        self.calls.append((start.year, start.month, index))
        if start.month == 1 and index == self.fail_index:
            raise NVDAPIError('Interrupción simulada')
        records = [cve(start.year, n) for n in range(1000, 1003)] if start.month == 1 else []
        return {'startIndex': index, 'totalResults': len(records),
                'vulnerabilities': [{'cve': item} for item in records[index:index + self.page_size]]}


class DownloadTests(unittest.TestCase):
    def test_windows_cover_leap_year_without_gaps_and_cutoff(self):
        windows = list(monthly_windows(2024, parse_date('2026-10-05T00:00:00Z')))
        self.assertEqual(len(windows), 12)
        self.assertEqual(windows[1][2].day, 29)
        for previous, current in zip(windows, windows[1:]):
            self.assertAlmostEqual((current[1] - previous[2]).total_seconds(), .001)
        current = list(monthly_windows(2026, parse_date('2026-10-05T00:00:00Z')))
        self.assertEqual(len(current), 10)
        self.assertEqual(iso_date(current[-1][2]), '2026-10-05T00:00:00.000Z')

    def test_inclusion_accepts_any_network_v3_and_rejects_other_states(self):
        record = cve()
        record['metrics']['cvssMetricV31'][0]['cvssData']['attackVector'] = 'LOCAL'
        record['metrics']['cvssMetricV30'] = [{'cvssData': {'version': '3.0', 'attackVector': 'NETWORK'}}]
        self.assertIsNone(eligibility(record))
        for status in ['Received', 'Deferred', 'Rejected', 'Awaiting Analysis', 'Undergoing Analysis']:
            self.assertEqual(eligibility(cve(vulnStatus=status)), 'estado')
        for vector in ['LOCAL', 'PHYSICAL', 'ADJACENT_NETWORK']:
            record = cve()
            record['metrics']['cvssMetricV31'][0]['cvssData']['attackVector'] = vector
            self.assertEqual(eligibility(record), 'cvss_network')
        self.assertEqual(eligibility(cve(descriptions=[{'value': '  '}])), 'descripcion')
        self.assertEqual(eligibility(cve(references=[])), 'referencia')

    def test_references_require_tags_and_concrete_resources(self):
        for url in ['https://github.com/org/repo/blob/main/poc', 'https://gitlab.com/group/repo',
                    'https://bitbucket.org/group/repo', 'https://www.exploit-db.com/exploits/123']:
            self.assertTrue(valid_reference({'url': url, 'tags': ['Exploit']}), url)
            self.assertFalse(valid_reference({'url': url}), url)
        for url in ['https://github.com', 'https://github.com/owner', 'https://github.com/search/code',
                    'https://github.com.evil.example/owner/repo', 'https://exploit-db.com/exploits',
                    'https://user:secret@github.com/owner/repo', 'file:///tmp/advisory']:
            self.assertFalse(valid_reference({'url': url, 'tags': ['Exploit']}), url)

    def test_latest_observation_precedes_filter_and_tie_is_deterministic(self):
        old = cve()
        latest = cve(lastModified='2025-01-01T00:00:00Z', vulnStatus='Rejected')
        other = cve(number=1001)
        chosen, report = annual_sample([old, latest, other], 2023, parse_date('2026-01-01T00:00:00Z'), quota=1)
        self.assertEqual(chosen[0]['id'], other['id'])
        self.assertEqual(report['discarded']['estado'], 1)
        different = cve(descriptions=[{'value': 'Otra descripción'}])
        a, ra = annual_sample([old, different], 2023, parse_date('2026-01-01T00:00:00Z'), quota=1)
        b, rb = annual_sample([different, old], 2023, parse_date('2026-01-01T00:00:00Z'), quota=1)
        self.assertEqual(a, b)
        self.assertEqual(len(ra['equal_date_conflicts']), 1)

    def test_sampling_reproducible_without_duplicates_and_uses_publication_year(self):
        records = [cve(number=n) for n in range(1000, 1020)]
        records[0]['id'] = 'CVE-2020-9999'  # Publicado en 2023, aunque el ID diga 2020.
        cutoff = parse_date('2026-01-01T00:00:00Z')
        a, _ = annual_sample(records, 2023, cutoff, quota=10)
        b, _ = annual_sample(reversed(records), 2023, cutoff, quota=10)
        self.assertEqual(a, b)
        self.assertEqual(len({r['id'] for r in a}), 10)
        _, report = annual_sample(records, 2023, cutoff, quota=20)
        self.assertIn('CVE-2020-9999', report['selected_ids'])
        with self.assertRaisesRegex(ValueError, 'solo 20'):
            annual_sample(records, 2023, cutoff, quota=21)

    def test_pacing_retry_after_and_secret_only_in_headers(self):
        clock = Clock()
        session = Session([Response(429, headers={'Retry-After': '7'}), Response(), Response()])
        client = NVDClient('test-api-secret', session=session, sleep=clock.sleep, monotonic=clock.monotonic)
        date = parse_date('2023-01-01T00:00:00Z')
        client.page(date, date, 0)
        client.page(date, date, 0)
        self.assertEqual(clock.waits, [7.0, 6.0])
        self.assertEqual(session.headers['apiKey'], 'test-api-secret')
        self.assertTrue(all(url == API_URL and 'apiKey' not in args['params'] for url, args in session.calls))

    def test_transient_errors_retry_and_permanent_errors_stop(self):
        clock = Clock()
        session = Session([requests.Timeout('test-api-secret'), Response(503), Response()])
        client = NVDClient('test-api-secret', session=session, sleep=clock.sleep, monotonic=clock.monotonic)
        date = parse_date('2023-01-01T00:00:00Z')
        client.page(date, date, 0)
        self.assertEqual(len(session.calls), 3)
        for responses in [[Response(403)], [requests.Timeout('test-api-secret')] * 5]:
            clock = Clock()
            client = NVDClient('test-api-secret', session=Session(responses), sleep=clock.sleep, monotonic=clock.monotonic)
            with self.assertRaises(NVDAPIError) as error:
                client.page(date, date, 0)
            self.assertNotIn('test-api-secret', str(error.exception))

    def test_pagination_rejects_empty_early_page_and_wrong_offset(self):
        date = parse_date('2023-01-01T00:00:00Z')
        for payload in [{'startIndex': 0, 'totalResults': 3, 'vulnerabilities': []},
                        {'startIndex': 2, 'totalResults': 0, 'vulnerabilities': []}]:
            client = NVDClient('test', session=Session([Response(payload=payload)]))
            with self.assertRaises(NVDAPIError):
                client.page(date, date, 0)

    def test_cache_resume_integrity_and_reuse_without_new_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            cutoff = parse_date('2023-01-05T00:00:00Z')
            cache = PageCache(directory, (2023,), cutoff=cutoff, page_size=2)
            with self.assertRaises(NVDAPIError):
                list(cache.records(SimulatedAPI(fail_index=2), 2023))
            cache = PageCache(directory, (2023,), page_size=2)
            api = SimulatedAPI()
            self.assertEqual(len(list(cache.records(api, 2023))), 3)
            self.assertEqual(api.calls, [(2023, 1, 2)])
            api = SimulatedAPI()
            self.assertEqual(len(list(cache.records(api, 2023))), 3)
            self.assertEqual(api.calls, [])
            path = cache.run_directory / next(iter(cache.metadata['pages'].values()))['file']
            path.write_bytes(b'corrupted')
            with self.assertRaisesRegex(ValueError, 'dañada'):
                list(cache.records(api, 2023))

    def test_download_reports_quota_and_raw_cache_has_no_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            result = download_and_select(path, path, years=(2023,), quota=2,
                                         cutoff=parse_date('2023-01-05T00:00:00Z'), client=SimulatedAPI(), progress=lambda event: None)
            self.assertEqual(len(result.records), 2)
            self.assertEqual(result.report['annual']['2023']['eligible'], 3)
            self.assertTrue(json.loads((path / 'cache_nvd/manifiesto.json').read_text())['complete'])
            for file in path.rglob('*.json'):
                self.assertNotIn('apiKey', file.read_text())


class LoadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name)
        self.sources = self.path / 'fuentes'
        self.sources.mkdir()
        cwe_headers = ['CWE-ID', 'Name', 'Description', 'Extended Description', 'Potential Mitigations']
        weakness = ['120', 'Debilidad', 'Descripción', '', '::PHASE:Implementation:DESCRIPTION:Validar::']
        self.csv('cwe_hardware.csv', cwe_headers, [weakness])
        self.csv('cwe_software.csv', cwe_headers, [weakness, ['787', 'Otra', 'Descripción', '', '']])
        self.csv('capec.csv', ["'ID", 'Name', 'Description', 'Execution Flow', 'Prerequisites', 'Consequences', 'Related Weaknesses'],
                 [['10', 'Patrón', 'Descripción', '', '', '', '::120::200::200::']])
        self.csv('files_exploits.csv', ['id', 'description', 'codes'],
                 [['1', 'Título', 'CVE-2023-1000;CVE-2023-1001;CVE-2020-9999'],
                  ['1', 'Título', 'CVE-2023-1000;CVE-2023-1001;CVE-2020-9999'],
                  ['2', 'Otro', 'CVE-2024-1000;CVE-2024–1001'], ['3', 'Sin CVE', '']])
        (self.sources / 'NVDExample.json').write_text('{}')
        self.sample = selection([cve(y, n) for y in (2023, 2024) for n in (1000, 1001)])
        self.prepared = prepare_catalogue(self.sources, self.sample)
        self.database = self.path / 'catalogo.sqlite3'
        create_database(self.database)

    def tearDown(self):
        self.temporary.cleanup()

    def csv(self, name, headers, rows):
        with (self.sources / name).open('w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(headers)
            writer.writerows(rows)

    def snapshot(self):
        with sqlite3.connect(self.database) as connection:
            return {table: connection.execute(f'SELECT * FROM {table}').fetchall() for table in INSERT_COLUMNS}

    def load(self, prepared=None, sample=None):
        return load_catalogue(self.database, prepared or self.prepared, sample or self.sample,
                              self.path / 'salidas', progress=lambda event: None)

    def test_source_transformations_placeholders_and_multicve_exploits(self):
        rows = self.prepared.rows
        self.assertEqual(len(rows['MITRE_CWE']), 3)
        self.assertIn(('CWE-200', None, None, None, None), rows['MITRE_CWE'])
        self.assertEqual(len(rows['CAPEC_CWE']), 2)
        self.assertEqual(len(rows['EXPLOIT_DB']), 3)
        self.assertEqual(len(rows['EXPLOIT_CVE']), 3)
        self.assertEqual(self.prepared.diagnostics['duplicate_exploit_rows'], 1)
        self.assertEqual(self.prepared.diagnostics['duplicate_capec_links'], 1)
        self.assertEqual(self.prepared.diagnostics['exploit_cve_outside_sample'], ['CVE-2020-9999'])
        self.assertEqual(len(self.prepared.diagnostics['malformed_cve_codes']), 1)
        self.assertEqual(len(self.prepared.diagnostics['unresolved_weakness_values']), 4)
        for row in rows['NVD_CVE']:
            self.assertTrue(row[1].endswith('.000Z'))
            self.assertEqual(json.loads(row[7]), self.sample.records[0]['weaknesses'])

    def test_duplicate_conflicts_and_nonempty_extra_columns_fail(self):
        self.csv('files_exploits.csv', ['id', 'description', 'codes'], [['1', 'A', ''], ['1', 'B', '']])
        with self.assertRaisesRegex(ValueError, 'título incompatible'):
            prepare_catalogue(self.sources, self.sample)
        self.csv('cwe_software.csv', ['CWE-ID', 'Name', 'Description', 'Extended Description', 'Potential Mitigations'], [['120', 'Distinto', 'D', '', '']])
        with self.assertRaisesRegex(ValueError, 'campos incompatibles'):
            prepare_catalogue(self.sources, self.sample)
        (self.sources / 'capec.csv').write_text("'ID,Name\n1,Name,\n")
        self.assertEqual(read_csv(self.sources / 'capec.csv'), [{"'ID": '1', 'Name': 'Name'}])
        (self.sources / 'capec.csv').write_text("'ID,Name\n1,Name,unexpected\n")
        with self.assertRaisesRegex(ValueError, 'anchura'):
            read_csv(self.sources / 'capec.csv')

    def test_atomic_load_catalog_and_replacement_without_accumulation(self):
        report = self.load()
        self.assertEqual(report['validation']['annual_counts'], {'2023': 2, '2024': 2})
        with sqlite3.connect(self.database) as connection:
            catalog = connection.execute('SELECT id,cwes_json,exploits_json FROM VW_CVE_CATALOGO').fetchall()
            self.assertEqual(len(catalog), 4)
            first = next(r for r in catalog if r[0] == 'CVE-2023-1000')
            self.assertEqual(len(json.loads(first[1])), 2)
            self.assertEqual(len(json.loads(first[2])), 1)
        new_sample = selection([cve(y, n) for y in (2023, 2024) for n in (2000, 2001)])
        self.load(prepare_catalogue(self.sources, new_sample), new_sample)
        self.assertEqual({r[0] for r in self.snapshot()['NVD_CVE']}, {r['id'] for r in new_sample.records})
        self.assertEqual(len(self.snapshot()['NVD_CVE']), 4)
        self.assertEqual(len(list((self.path / 'salidas/respaldos').glob('*.sqlite3'))), 2)

    def test_quota_failure_does_not_touch_existing_database(self):
        self.load()
        before = self.database.read_bytes()
        incomplete = Selection(self.sample.records[:-1], self.sample.report)
        with self.assertRaisesRegex(ValueError, 'Muestra incompleta'):
            self.load(sample=incomplete)
        self.assertEqual(self.database.read_bytes(), before)

    def test_insert_failure_and_validation_failure_rollback_with_backup(self):
        self.load()
        before = self.snapshot()
        invalid = copy.deepcopy(self.prepared)
        invalid.rows['EXPLOIT_DB'].append((0, 'ID inválido'))
        with self.assertRaises(sqlite3.IntegrityError):
            self.load(prepared=invalid)
        self.assertEqual(self.snapshot(), before)
        with patch('carga_catalogo.validate_loaded', side_effect=ValueError('Validación simulada')):
            with self.assertRaisesRegex(ValueError, 'Validación simulada'):
                self.load()
        self.assertEqual(self.snapshot(), before)
        backup = sorted((self.path / 'salidas/respaldos').glob('*.sqlite3'))[-1]
        with sqlite3.connect(backup) as connection:
            self.assertEqual(connection.execute('SELECT count(*) FROM NVD_CVE').fetchone()[0], 4)

    def test_actual_csv_counts_and_original_hashes(self):
        result = prepare_catalogue(DIRECTORY / 'fuentes', self.sample)
        self.assertEqual(len(result.rows['MITRE_CAPEC']), 559)
        self.assertEqual(len(result.rows['EXPLOIT_DB']), 46698)
        self.assertEqual(len(result.rows['CAPEC_CWE']), 1212)
        self.assertEqual(result.diagnostics['cwe_with_source_context'], 501)
        initial = json.loads((DIRECTORY / 'revision_fuentes.json').read_text())
        self.assertEqual(result.source_hashes, {name: metadata['sha256'] for name, metadata in initial['files'].items()})


if __name__ == '__main__':
    unittest.main()
