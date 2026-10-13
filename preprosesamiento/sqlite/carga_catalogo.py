"""Descarga reproducible de NVD y carga atómica del catálogo SQLite v1.

El notebook presenta las etapas; este módulo no depende de Chroma ni de pandas.
La clave NVD nunca forma parte de URLs, cachés, informes o mensajes de error.
"""
from __future__ import annotations

import calendar
import csv
import gzip
import hashlib
import json
import random
import re
import sqlite3
import time
from collections import Counter
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlparse

import requests
from dotenv import dotenv_values

DIRECTORY = Path(__file__).resolve().parent
API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
YEARS = (2023, 2024, 2025, 2026)
JSON_FIELDS = ('descriptions', 'metrics', 'weaknesses', 'configurations', 'references')
CVE_PATTERN = re.compile(r'CVE-[0-9]{4}-[0-9]{4,}', re.ASCII)
CWE_PATTERN = re.compile(r'CWE-[1-9][0-9]*', re.ASCII)
CWE_FIELDS = ('Name', 'Description', 'Extended Description', 'Potential Mitigations')
SOURCE_NAMES = ('cwe_hardware.csv', 'cwe_software.csv', 'capec.csv', 'files_exploits.csv', 'NVDExample.json')
FILTERS = {
    'version': 1, 'statuses': ['Analyzed', 'Modified'],
    'cvss_versions': ['3.0', '3.1'], 'attack_vector': 'NETWORK',
    'references': 'Vendor Advisory OR Exploit in GitHub/GitLab/Bitbucket/ExploitDB',
    'description': 'at least one nonempty value',
}
INSERT_COLUMNS = {
    'MITRE_CWE': ('id', 'name', 'description', 'extended_description', 'potential_mitigations'),
    'MITRE_CAPEC': ('id', 'name', 'description', 'execution_flow', 'prerequisites', 'consequences'),
    'NVD_CVE': ('id', 'published', 'last_modified', 'vuln_status', 'source_identifier',
                'descriptions_json', 'metrics_json', 'weaknesses_json', 'configurations_json', 'references_json'),
    'EXPLOIT_DB': ('id', 'description'),
    'CAPEC_CWE': ('capec_id', 'cwe_id'),
    'CVE_CWE': ('cve_id', 'cwe_id'),
    'EXPLOIT_CVE': ('exploit_id', 'cve_id'),
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_date(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError('Fecha NVD ausente o inválida')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return (parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed).astimezone(timezone.utc)


def iso_date(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False), encoding='utf-8')
    temporary.replace(path)


def fingerprint(value) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def monthly_windows(year: int, cutoff: datetime):
    cutoff = cutoff.astimezone(timezone.utc)
    for month in range(1, 13):
        start = datetime(year, month, 1, tzinfo=timezone.utc)
        end = start + timedelta(days=calendar.monthrange(year, month)[1]) - timedelta(milliseconds=1)
        if start > cutoff:
            break
        yield month, start, min(end, cutoff)


def valid_reference(reference) -> bool:
    if not isinstance(reference, dict) or not isinstance(reference.get('url'), str):
        return False
    try:
        parsed = urlparse(reference['url'])
        host = (parsed.hostname or '').lower()
        # Validar puertos y rechazar credenciales incrustadas.
        parsed.port
    except ValueError:
        return False
    if parsed.scheme not in {'http', 'https'} or '.' not in host or parsed.username or parsed.password:
        return False
    tags = reference.get('tags', [])
    if not isinstance(tags, list):
        return False
    if 'Vendor Advisory' in tags:
        return True
    if 'Exploit' not in tags:
        return False
    segments = [part for part in parsed.path.split('/') if part]
    if host in {'github.com', 'gitlab.com', 'bitbucket.org'}:
        reserved = {'login', 'search', 'settings', 'topics', 'users', 'orgs', 'marketplace', 'explore', '-'}
        return len(segments) >= 2 and segments[0].lower() not in reserved
    return host in {'exploit-db.com', 'www.exploit-db.com'} and bool(
        re.fullmatch(r'/exploits/[1-9][0-9]*/?', parsed.path)
    )


def eligibility(cve: dict) -> str | None:
    """Primera causa de exclusión; None indica que cumple todos los filtros."""
    if cve.get('vulnStatus') not in {'Analyzed', 'Modified'}:
        return 'estado'
    descriptions = cve.get('descriptions')
    if not isinstance(descriptions, list) or not any(
        isinstance(d, dict) and isinstance(d.get('value'), str) and d['value'].strip() for d in descriptions
    ):
        return 'descripcion'
    metrics = cve.get('metrics')
    network = False
    if isinstance(metrics, dict):
        for family, version in [('cvssMetricV30', '3.0'), ('cvssMetricV31', '3.1')]:
            entries = metrics.get(family, [])
            if not isinstance(entries, list):
                continue
            for entry in entries:
                data = entry.get('cvssData') if isinstance(entry, dict) else None
                if isinstance(data, dict) and data.get('version') == version and data.get('attackVector') == 'NETWORK':
                    network = True
    if not network:
        return 'cvss_network'
    references = cve.get('references')
    if not isinstance(references, list) or not any(valid_reference(r) for r in references):
        return 'referencia'
    for field in JSON_FIELDS:
        value = cve.get(field)
        expected = dict if field == 'metrics' else list
        if value is not None and not isinstance(value, expected):
            return 'estructura_json'
    return None


class NVDAPIError(RuntimeError):
    pass


class NVDClient:
    def __init__(self, key: str, *, session=None, sleep=time.sleep, monotonic=time.monotonic,
                 pace_seconds=6.0, page_size=2000, progress: Callable[[dict], None] | None = None):
        if not key or not key.strip():
            raise ValueError('Falta API_KEY_NVD en el .env de la raíz')
        self.session = session or requests.Session()
        self.session.headers.update({'apiKey': key.strip(), 'User-Agent': 'tesis-cve-sqlite/1.0'})
        self.sleep, self.monotonic = sleep, monotonic
        self.pace_seconds, self.page_size = pace_seconds, page_size
        self.progress = progress or (lambda event: None)
        self.last_request = None

    @classmethod
    def from_env(cls, project_root: Path, **kwargs):
        return cls(dotenv_values(project_root / '.env').get('API_KEY_NVD'), **kwargs)

    def close(self):
        self.session.close()

    def _wait(self, delay: float):
        # Pausas largas se dividen para emitir progreso durante Retry-After.
        while delay > 0:
            step = min(delay, 30.0)
            self.progress({'phase': 'wait', 'seconds': step})
            self.sleep(step)
            delay -= step

    def _pace(self):
        if self.last_request is not None:
            self._wait(max(0.0, self.pace_seconds - (self.monotonic() - self.last_request)))
        self.last_request = self.monotonic()

    @staticmethod
    def retry_delay(header, fallback):
        try:
            return max(0.0, float(header))
        except (TypeError, ValueError):
            try:
                return max(0.0, (parsedate_to_datetime(header).astimezone(timezone.utc) - utc_now()).total_seconds())
            except (TypeError, ValueError, OverflowError):
                return fallback

    def page(self, start: datetime, end: datetime, index: int) -> dict:
        params = {'pubStartDate': iso_date(start), 'pubEndDate': iso_date(end),
                  'startIndex': index, 'resultsPerPage': self.page_size}
        for attempt in range(5):
            self._pace()
            try:
                response = self.session.get(API_URL, params=params, timeout=(10, 45))
            except (requests.Timeout, requests.ConnectionError):
                if attempt == 4:
                    raise NVDAPIError('NVD: se agotaron los reintentos de conexión') from None
                self._wait(2.0 ** attempt)
                continue
            except requests.RequestException:
                raise NVDAPIError('NVD: fallo de solicitud HTTP') from None
            if response.status_code in {429, 500, 502, 503, 504}:
                if attempt == 4:
                    raise NVDAPIError(f'NVD: se agotaron los reintentos HTTP {response.status_code}')
                self._wait(self.retry_delay(response.headers.get('Retry-After'), 2.0 ** attempt))
                continue
            if response.status_code != 200:
                raise NVDAPIError(f'NVD: respuesta permanente HTTP {response.status_code}')
            try:
                payload = response.json()
            except ValueError:
                raise NVDAPIError('NVD: respuesta no contiene JSON válido') from None
            if not isinstance(payload, dict) or not isinstance(payload.get('vulnerabilities'), list):
                raise NVDAPIError('NVD: estructura de respuesta inválida')
            total = payload.get('totalResults')
            if type(total) is not int or total < 0 or payload.get('startIndex') != index:
                raise NVDAPIError('NVD: metadatos de paginación inválidos')
            if any(not isinstance(r, dict) or not isinstance(r.get('cve'), dict) for r in payload['vulnerabilities']):
                raise NVDAPIError('NVD: elemento de vulnerabilidad inválido')
            if not payload['vulnerabilities'] and index < total:
                raise NVDAPIError('NVD: página vacía antes del final')
            return payload
        raise NVDAPIError('NVD: descarga incompleta')


class PageCache:
    def __init__(self, directory: Path, years=YEARS, *, refresh=False, cutoff=None, page_size=2000):
        self.directory = directory
        self.pointer = directory / 'manifiesto.json'
        compatible = False
        if self.pointer.exists() and not refresh:
            metadata = json.loads(self.pointer.read_text(encoding='utf-8'))
            compatible = (metadata.get('cache_version') == 1 and metadata.get('years') == list(years)
                          and metadata.get('page_size') == page_size and metadata.get('endpoint') == API_URL
                          and (cutoff is None or metadata.get('cutoff') == iso_date(cutoff)))
        if compatible:
            self.metadata = metadata
        else:
            now = utc_now()
            self.metadata = {
                'cache_version': 1, 'endpoint': API_URL, 'years': list(years), 'page_size': page_size,
                'cutoff': iso_date(cutoff or now), 'created_at': iso_date(now),
                'run': now.strftime('%Y%m%dT%H%M%S%fZ'), 'pages': {}, 'complete': False,
            }
        self.run_directory = self.directory / self.metadata['run']
        self.save()

    @property
    def cutoff(self):
        return parse_date(self.metadata['cutoff'])

    def save(self):
        write_json(self.run_directory / 'manifiesto.json', self.metadata)
        write_json(self.pointer, self.metadata)

    def get_page(self, client: NVDClient, year, month, start, end, index):
        key = f'{year}-{month:02d}-{index:07d}'
        query = {'start': iso_date(start), 'end': iso_date(end), 'index': index}
        entry = self.metadata['pages'].get(key)
        if entry is not None:
            path = self.run_directory / entry['file']
            if entry['query'] != query or not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
                raise ValueError('Caché NVD incompatible o dañada; usar REFRESCAR_NVD=True')
            with gzip.open(path, 'rt', encoding='utf-8') as file:
                return json.load(file)
        payload = client.page(start, end, index)
        filename = key + '.json.gz'
        path = self.run_directory / filename
        temporary = path.with_name(path.name + '.tmp')
        with gzip.open(temporary, 'wt', encoding='utf-8') as file:
            json.dump(payload, file, ensure_ascii=False, allow_nan=False)
        temporary.replace(path)
        self.metadata['pages'][key] = {
            'file': filename, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'query': query,
            'records': len(payload['vulnerabilities']), 'total_results': payload['totalResults'],
        }
        self.metadata['last_page'] = key
        self.save()
        client.progress({'phase': 'download', 'year': year, 'month': month, 'index': index,
                         'records': len(payload['vulnerabilities']), 'cached_pages': len(self.metadata['pages'])})
        return payload

    def records(self, client: NVDClient, year: int):
        for month, start, end in monthly_windows(year, self.cutoff):
            index = 0
            while True:
                payload = self.get_page(client, year, month, start, end, index)
                yield from (item['cve'] for item in payload['vulnerabilities'])
                count = len(payload['vulnerabilities'])
                if not count and index < payload['totalResults']:
                    raise NVDAPIError('NVD: caché con página vacía antes del final')
                index += count
                if index >= payload['totalResults']:
                    break


def project_cve(cve: dict) -> dict:
    return {field: cve[field] for field in ('id', 'published', 'lastModified', 'vulnStatus', 'sourceIdentifier', *JSON_FIELDS) if field in cve}


def annual_sample(records: Iterable[dict], year: int, cutoff: datetime, *, quota=250, seed=42):
    # Guardar contenido completo solo para elegibles; para el resto basta la
    # observación más reciente y su motivo. Así no se acumulan cuatro años en RAM.
    observations = {}
    conflicts, invalid, duplicates = [], Counter(), 0
    fetched = 0
    for cve in records:
        fetched += 1
        cve_id = cve.get('id')
        if not isinstance(cve_id, str) or not CVE_PATTERN.fullmatch(cve_id):
            invalid['id_invalido'] += 1
            continue
        try:
            published, modified = parse_date(cve.get('published')), parse_date(cve.get('lastModified'))
        except (TypeError, ValueError):
            invalid['fecha_invalida'] += 1
            continue
        reason = 'fuera_de_anio' if published.year != year or published > cutoff else eligibility(cve)
        signature = fingerprint(cve)
        previous = observations.get(cve_id)
        if previous:
            duplicates += 1
            if modified == previous[0] and signature != previous[1]:
                conflicts.append({'id': cve_id, 'last_modified': iso_date(modified), 'hashes': sorted([signature, previous[1]])})
            # Desempate determinista por hash; no depende del orden de las páginas.
            if modified < previous[0] or (modified == previous[0] and signature >= previous[1]):
                continue
        observations[cve_id] = (modified, signature, project_cve(cve) if reason is None else None, reason)
    candidates = sorted((r[2] for r in observations.values() if r[2] is not None), key=lambda cve: cve['id'])
    discarded = Counter(r[3] for r in observations.values() if r[3] is not None) + invalid
    report = {
        'year': year, 'records_downloaded': fetched, 'unique_valid_ids': len(observations),
        'duplicate_observations': duplicates, 'eligible': len(candidates), 'discarded': dict(discarded),
        'equal_date_conflicts': conflicts, 'seed': seed + year,
        'population_hash': fingerprint([c['id'] for c in candidates]),
    }
    if len(candidates) < quota:
        raise ValueError(f'{year}: solo {len(candidates)} CVE elegibles; se requieren {quota}. SQLite no se modificó.')
    chosen = sorted(random.Random(seed + year).sample(candidates, quota), key=lambda cve: cve['id'])
    report.update({'selected': len(chosen), 'selected_ids': [c['id'] for c in chosen]})
    return chosen, report


@dataclass
class Selection:
    records: list[dict]
    report: dict


def download_and_select(project_root: Path, output_directory: Path, *, years=YEARS, quota=250,
                        seed=42, refresh=False, cutoff=None, client=None, progress=None) -> Selection:
    progress = progress or (lambda event: print(json.dumps(event, ensure_ascii=False), flush=True))
    owned_client = client is None
    client = client or NVDClient.from_env(project_root, progress=progress)
    try:
        cache = PageCache(output_directory / 'cache_nvd', years, refresh=refresh, cutoff=cutoff, page_size=client.page_size)
        selected, reports = [], {}
        for year in years:
            records, report = annual_sample(cache.records(client, year), year, cache.cutoff, quota=quota, seed=seed)
            selected.extend(records)
            reports[str(year)] = report
            progress({'phase': 'selection', 'year': year, 'eligible': report['eligible'], 'selected': len(records)})
        if len({c['id'] for c in selected}) != len(selected):
            raise ValueError('Un ID CVE aparece en varias cuotas anuales; SQLite no se modificó')
        cache.metadata['complete'] = True
        cache.save()
        report = {'cutoff': iso_date(cache.cutoff), 'seed': seed, 'quota': quota, 'years': list(years),
                  'filters': FILTERS, 'annual': reports, 'cache_run': cache.metadata['run'],
                  'cached_pages': len(cache.metadata['pages'])}
        write_json(output_directory / 'seleccion_nvd.json', report)
        return Selection(selected, report)
    finally:
        if owned_client:
            client.close()


def read_csv(path: Path) -> list[dict]:
    with path.open(encoding='utf-8-sig', newline='') as file:
        reader = csv.DictReader(file)
        rows = list(reader)
    for number, row in enumerate(rows, 1):
        extra = row.pop(None, None)
        allowed_extra = path.name in {'capec.csv', 'cwe_hardware.csv', 'cwe_software.csv'} and extra == ['']
        if (extra is not None and not allowed_extra) or any(value is None for value in row.values()):
            raise ValueError(f'{path.name}: registro {number} tiene una anchura inesperada')
    return rows


def optional_text(value: str):
    return value if value.strip() else None


def positive_id(value: str) -> int:
    if not value.isascii() or not value.isdigit() or int(value) <= 0:
        raise ValueError('Identificador numérico de fuente inválido')
    return int(value)


@dataclass
class Prepared:
    rows: dict[str, list[tuple]]
    diagnostics: dict
    source_hashes: dict


def prepare_catalogue(source_directory: Path, selection: Selection) -> Prepared:
    hashes = {name: hashlib.sha256((source_directory / name).read_bytes()).hexdigest() for name in SOURCE_NAMES}
    rows = {table: [] for table in INSERT_COLUMNS}
    weaknesses, patterns, exploits = {}, {}, {}
    capec_links, cve_links, exploit_links = set(), set(), set()
    diagnostics = {'source_rows': {}, 'cwe_overlap_ids': [], 'malformed_cve_codes': [],
                   'unresolved_weakness_values': [], 'duplicate_exploit_rows': 0, 'duplicate_capec_links': 0}
    for filename in ['cwe_hardware.csv', 'cwe_software.csv']:
        source = read_csv(source_directory / filename)
        diagnostics['source_rows'][filename] = len(source)
        file_ids = set()
        for record in source:
            key = 'CWE-' + str(positive_id(record['CWE-ID']))
            if key in file_ids:
                raise ValueError(f'{filename}: CWE repetido {key}')
            file_ids.add(key)
            value = (key, *(optional_text(record[field]) for field in CWE_FIELDS))
            if value[1] is None or value[2] is None:
                raise ValueError(f'{filename}: falta contexto básico de {key}')
            if key in weaknesses:
                if weaknesses[key] != value:
                    raise ValueError(f'CWE con campos incompatibles: {key}')
                diagnostics['cwe_overlap_ids'].append(key)
            weaknesses[key] = value
    original_cwe = set(weaknesses)
    source = read_csv(source_directory / 'capec.csv')
    diagnostics['source_rows']['capec.csv'] = len(source)
    for record in source:
        key = positive_id(record.get("'ID", record.get('ID', '')))
        if key in patterns:
            raise ValueError(f'CAPEC repetido: {key}')
        patterns[key] = (key, record['Name'], *(optional_text(record[field]) for field in ['Description', 'Execution Flow', 'Prerequisites', 'Consequences']))
        for token in record['Related Weaknesses'].split('::'):
            if not token:
                continue
            pair = key, 'CWE-' + str(positive_id(token))
            diagnostics['duplicate_capec_links'] += pair in capec_links
            capec_links.add(pair)
    selected_ids = {c['id'] for c in selection.records}
    outside = set()
    source = read_csv(source_directory / 'files_exploits.csv')
    diagnostics['source_rows']['files_exploits.csv'] = len(source)
    for record in source:
        key = positive_id(record['id'])
        value = key, record['description']
        if key in exploits:
            diagnostics['duplicate_exploit_rows'] += 1
            if exploits[key] != value:
                raise ValueError(f'Exploit con título incompatible: {key}')
        exploits[key] = value
        for token in record['codes'].split(';'):
            code = token.strip()
            if 'CVE' in token.upper() and not CVE_PATTERN.fullmatch(token):
                diagnostics['malformed_cve_codes'].append({'exploit_id': key, 'raw_token': token, 'valid_after_trim': bool(CVE_PATTERN.fullmatch(code))})
            if not CVE_PATTERN.fullmatch(code):
                continue
            if code in selected_ids:
                exploit_links.add((key, code))
            else:
                outside.add(code)
    for cve in selection.records:
        if eligibility(cve) is not None:
            raise ValueError(f'CVE seleccionado no elegible: {cve["id"]}')
        rows['NVD_CVE'].append((
            cve['id'], iso_date(parse_date(cve['published'])), iso_date(parse_date(cve['lastModified'])),
            cve['vulnStatus'], cve.get('sourceIdentifier'),
            *(json.dumps(cve[field], ensure_ascii=False, allow_nan=False) if cve.get(field) is not None else None for field in JSON_FIELDS),
        ))
        for group in cve.get('weaknesses') or []:
            if not isinstance(group, dict) or not isinstance(group.get('description', []), list):
                raise ValueError(f'Estructura de weaknesses inválida: {cve["id"]}')
            for description in group.get('description', []):
                value = description.get('value') if isinstance(description, dict) else None
                if isinstance(value, str) and CWE_PATTERN.fullmatch(value):
                    cve_links.add((cve['id'], value))
                else:
                    diagnostics['unresolved_weakness_values'].append({'cve_id': cve['id'], 'value': value})
    referenced = {key for _, key in capec_links} | {key for _, key in cve_links}
    for key in referenced - original_cwe:
        weaknesses[key] = (key, None, None, None, None)
    rows['MITRE_CWE'] = sorted(weaknesses.values(), key=lambda row: int(row[0][4:]))
    rows['MITRE_CAPEC'] = sorted(patterns.values())
    rows['EXPLOIT_DB'] = sorted(exploits.values())
    rows['CAPEC_CWE'] = sorted(capec_links)
    rows['CVE_CWE'] = sorted(cve_links)
    rows['EXPLOIT_CVE'] = sorted(exploit_links)
    diagnostics.update({'cwe_with_source_context': len(original_cwe),
                        'placeholder_cwe_ids': sorted(referenced - original_cwe),
                        'exploit_cve_outside_sample': sorted(outside),
                        'exploit_cve_outside_sample_count': len(outside)})
    return Prepared(rows, diagnostics, hashes)


def validate_loaded(connection: sqlite3.Connection, prepared: Prepared, selection: Selection) -> dict:
    if connection.execute('PRAGMA foreign_keys').fetchone()[0] != 1:
        raise ValueError('Las claves foráneas no están activadas')
    if connection.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
        raise ValueError('Falló integrity_check')
    if connection.execute('PRAGMA foreign_key_check').fetchall():
        raise ValueError('Hay claves foráneas inválidas')
    counts = {table: connection.execute(f'SELECT count(*) FROM {table}').fetchone()[0] for table in INSERT_COLUMNS}
    if counts != {table: len(values) for table, values in prepared.rows.items()}:
        raise ValueError('Los conteos de tablas no coinciden con las filas preparadas')
    catalog_count = connection.execute('SELECT count(*) FROM VW_CVE_CATALOGO').fetchone()[0]
    if catalog_count != counts['NVD_CVE']:
        raise ValueError('El catálogo no tiene exactamente una fila por CVE')
    columns = INSERT_COLUMNS['NVD_CVE']
    stored = connection.execute(f'SELECT {", ".join(columns)} FROM NVD_CVE ORDER BY id').fetchall()
    if stored != sorted(prepared.rows['NVD_CVE']):
        raise ValueError('Los registros CVE almacenados no coinciden con la muestra')
    annual = Counter()
    cutoff = parse_date(selection.report['cutoff'])
    for row in stored:
        record = {'id': row[0], 'published': row[1], 'lastModified': row[2], 'vulnStatus': row[3]}
        record.update({field: json.loads(value) if value is not None else None for field, value in zip(JSON_FIELDS, row[5:])})
        if eligibility(record) is not None or parse_date(row[1]) > cutoff:
            raise ValueError(f'El CVE {row[0]} no cumple la admisión de la muestra')
        annual[parse_date(row[1]).year] += 1
    expected = {year: selection.report['quota'] for year in selection.report['years']}
    if dict(annual) != expected:
        raise ValueError('No se cumplen las cuotas anuales exactas')
    for table in ['CAPEC_CWE', 'CVE_CWE', 'EXPLOIT_CVE']:
        if set(connection.execute(f'SELECT * FROM {table}').fetchall()) != set(prepared.rows[table]):
            raise ValueError(f'Las asociaciones de {table} no coinciden con las fuentes')
    coverage = {
        'cve_with_cwe': connection.execute('SELECT count(DISTINCT cve_id) FROM CVE_CWE').fetchone()[0],
        'cve_with_capec': connection.execute('SELECT count(DISTINCT cw.cve_id) FROM CVE_CWE cw JOIN CAPEC_CWE pc ON pc.cwe_id=cw.cwe_id').fetchone()[0],
        'cve_with_exploit': connection.execute('SELECT count(DISTINCT cve_id) FROM EXPLOIT_CVE').fetchone()[0],
        'cpe_rows': connection.execute('SELECT count(*) FROM VW_CVE_CPE').fetchone()[0],
        'cwe_without_context': connection.execute('SELECT count(*) FROM MITRE_CWE WHERE name IS NULL').fetchone()[0],
    }
    return {'table_counts': counts, 'catalog_count': catalog_count,
            'annual_counts': {str(y): annual[y] for y in sorted(annual)},
            'integrity_check': 'ok', 'foreign_key_check': [], 'coverage': coverage}


def load_catalogue(database: Path, prepared: Prepared, selection: Selection,
                   output_directory: Path, *, progress=None) -> dict:
    progress = progress or (lambda event: print(json.dumps(event, ensure_ascii=False), flush=True))
    # Antes de abrir SQLite se comprueba que ninguna cuota está incompleta.
    counts = Counter(parse_date(c['published']).year for c in selection.records)
    if dict(counts) != {year: selection.report['quota'] for year in selection.report['years']}:
        raise ValueError('Muestra incompleta: SQLite no se modificó')
    if not database.exists():
        raise FileNotFoundError('No existe la base; crear primero el esquema con crear_base.py')
    output_directory.mkdir(parents=True, exist_ok=True)
    run_id = utc_now().strftime('%Y%m%dT%H%M%S%fZ')
    backup_path = output_directory / 'respaldos' / f'catalogo_{run_id}.sqlite3'
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(database)) as connection:
        connection.execute('PRAGMA foreign_keys = ON')
        if connection.execute('PRAGMA user_version').fetchone()[0] != 1:
            raise ValueError('La base no usa el esquema v1')
        actual_tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        if actual_tables != set(INSERT_COLUMNS):
            raise ValueError('El esquema de tablas no corresponde al catálogo')
        with closing(sqlite3.connect(backup_path)) as backup:
            connection.backup(backup)
        try:
            connection.execute('BEGIN IMMEDIATE')
            for table in reversed(INSERT_COLUMNS):
                connection.execute(f'DELETE FROM {table}')
            for table, columns in INSERT_COLUMNS.items():
                sql = f'INSERT INTO {table} ({", ".join(columns)}) VALUES ({", ".join("?" for _ in columns)})'
                connection.executemany(sql, prepared.rows[table])
                progress({'phase': 'insert', 'table': table, 'rows': len(prepared.rows[table])})
            validation = validate_loaded(connection, prepared, selection)
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
    report = {'run_id': run_id, 'completed_at': iso_date(utc_now()), 'backup_file': str(backup_path),
              'selection': selection.report, 'source_hashes': prepared.source_hashes,
              'diagnostics': prepared.diagnostics, 'validation': validation}
    write_json(output_directory / f'informe_carga_{run_id}.json', report)
    write_json(output_directory / 'informe_carga.json', report)
    lines = ['# Validación de la carga SQLite', '', f'Fecha de corte UTC: {selection.report["cutoff"]}.',
             f'Semilla base: {selection.report["seed"]}.', '', '| Año de publicación | Elegibles | Insertados |', '| --- | ---: | ---: |']
    for year in selection.report['years']:
        details = selection.report['annual'][str(year)]
        lines.append(f'| {year} | {details["eligible"]} | {validation["annual_counts"][str(year)]} |')
    lines.extend(['', '| Tabla | Registros |', '| --- | ---: |'])
    lines.extend(f'| {table} | {count} |' for table, count in validation['table_counts'].items())
    lines.extend(['', f'Filas del catálogo: {validation["catalog_count"]}.',
                  'Integridad: `ok`. Errores de FK: 0.', '', '## Cobertura', ''])
    lines.extend(f'- {key}: {value}.' for key, value in validation['coverage'].items())
    lines.extend(['', 'El informe JSON conserva hashes, filtros, IDs seleccionados, descartes por año,',
                  'anomalías de los CSV, debilidades sin contexto y CVE de ExploitDB fuera de la muestra.',
                  'Ninguna asociación se infiere por similitud textual.', ''])
    (output_directory / 'informe_carga.md').write_text('\n'.join(lines), encoding='utf-8')
    return report
