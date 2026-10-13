"""Catálogo SQLite → Chroma: preparación local, respaldo y carga reanudable."""
from __future__ import annotations
import collections
import datetime as dt
import gzip
import hashlib
import json
from pathlib import Path
import sqlite3
import numpy as np

MODEL = 'sentence-transformers/all-MiniLM-L6-v2'
OLD_COLLECTION = 'nvd_cve_2023_2026'
COLLECTION = 'catalogo_cve_2023_2026'
MAX_TOKENS = 240
OVERLAP = 30


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='milliseconds')


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def file_hash(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def save_json(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    temp.replace(path)


def catalogue(db):
    with sqlite3.connect(f'file:{Path(db).resolve()}?mode=ro', uri=True) as c:
        c.row_factory = sqlite3.Row
        if c.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('SQLite no supera integrity_check')
        if c.execute('PRAGMA foreign_key_check').fetchall():
            raise ValueError('SQLite contiene claves foráneas inválidas')
        rows = [dict(r) for r in c.execute('SELECT * FROM VW_CVE_CATALOGO ORDER BY id')]
        cpes = [dict(r) for r in c.execute('SELECT * FROM VW_CVE_CPE ORDER BY cve_id,json_path')]
    years = collections.Counter(int(r['published'][:4]) for r in rows)
    if years != {2023: 250, 2024: 250, 2025: 250, 2026: 250}:
        raise ValueError(f'Cuota SQLite inesperada: {dict(years)}')
    return rows, cpes


def network_metric(metrics):
    choices = [m for key in ('cvssMetricV30', 'cvssMetricV31') for m in metrics.get(key, [])
               if m.get('cvssData', {}).get('attackVector') == 'NETWORK']
    if not choices:
        raise ValueError('CVE sin CVSS 3 NETWORK')
    return sorted(choices, key=lambda m: (-float(m['cvssData']['baseScore']),
                  m.get('type') != 'Primary', m['cvssData'].get('version') != '3.1', m.get('source', ''), digest(m)))[0]


def split_text(text, prefix, tokenizer, maximum=MAX_TOKENS, overlap=OVERLAP):
    """Fragmenta por offsets del texto original; nunca decodifica ni trunca texto."""
    if not text or not text.strip():
        return []
    encoded = tokenizer.encode(text, add_special_tokens=False)
    offsets = encoded.offsets
    if not offsets:
        return []
    result = []; start = 0; last_end = 0
    while start < len(offsets):
        end = min(len(offsets), start + maximum)
        char_start = 0 if start == 0 else offsets[start][0]
        while end > start:
            char_end = len(text) if end == len(offsets) else offsets[end][0]
            document = prefix + text[char_start:char_end]
            if len(tokenizer.encode(document).ids) <= maximum:
                break
            end -= 1
        if end == start:
            raise ValueError('Encabezado o token no cabe en el fragmento')
        result.append(document)
        last_end = end
        if end == len(offsets):
            break
        start = max(start + 1, end - min(overlap, max(0, end - start - 1)))
    assert last_end == len(offsets)
    return result


def tokenizer_and_model():
    from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2
    from tokenizers import Tokenizer
    model = ONNXMiniLM_L6_V2(preferred_providers=['CPUExecutionProvider'])
    # Descarga/verifica los artefactos antes de retirar cualquier colección.
    model._download_model_if_not_exists()
    options = model.ort.SessionOptions()
    options.intra_op_num_threads = 8
    options.inter_op_num_threads = 1
    options.log_severity_level = 3
    model.__dict__['model'] = model.ort.InferenceSession(
        str(Path(model.DOWNLOAD_PATH) / model.EXTRACTED_FOLDER_NAME / 'model.onnx'),
        sess_options=options, providers=['CPUExecutionProvider'])
    model(['Model readiness check.'])
    tokenizer = Tokenizer.from_str(model.tokenizer.to_str())
    tokenizer.no_padding(); tokenizer.no_truncation()
    model_hash = file_hash(Path(model.DOWNLOAD_PATH) / model.EXTRACTED_FOLDER_NAME / 'model.onnx')
    return tokenizer, model, model_hash


def prepare(db, out, tokenizer, model_hash):
    out = Path(out); rows, cpes = catalogue(db)
    spec = {'catalogue_hash': digest({'rows': rows, 'cpes': cpes}), 'model': MODEL, 'model_hash': model_hash,
            'tokenizer_hash': hashlib.sha256(tokenizer.to_str().encode()).hexdigest(),
            'max_tokens': MAX_TOKENS, 'overlap': OVERLAP, 'transform_version': 2, 'space': 'cosine'}
    run_id = digest(spec)
    run = out / 'cargas' / run_id
    cached_manifest = run / 'manifiesto.json'
    cached_documents = run / 'documentos.json.gz'
    if cached_manifest.exists() and cached_documents.exists():
        manifest = json.loads(cached_manifest.read_text())
        if any(manifest.get(k) != v for k, v in spec.items()):
            raise ValueError('Manifiesto de preparación incompatible')
        with gzip.open(cached_documents, 'rt', encoding='utf-8') as f: records = json.load(f)
        if len(records) != manifest['document_count'] or digest(records) != manifest['documents_hash']:
            raise ValueError('Caché documental inválida')
        manifest.update(sqlite_file_hash=file_hash(db), sqlite_path=str(Path(db).resolve()))
        save_json(cached_manifest, manifest)
        return records, manifest, run
    cpemap = collections.defaultdict(list)
    for item in cpes:
        cpemap[item['cve_id']].append(item)
    records = []; missing = []; coverage = collections.Counter()
    for row in rows:
        cve = row['id']; metric = network_metric(json.loads(row['metrics_json']))
        data = metric['cvssData']
        refs = json.loads(row['references_json'] or '[]')
        valid_refs = [r for r in refs if r.get('url', '').startswith(('http://', 'https://'))]
        source_url = next((r['url'] for r in valid_refs if 'Vendor Advisory' in r.get('tags', [])),
                          valid_refs[0]['url'] if valid_refs else '')
        meta = {'cve_id': cve, 'published_year': int(row['published'][:4]),
                'published': row['published'], 'last_modified': row['last_modified'],
                'published_ts': dt.datetime.fromisoformat(row['published'].replace('Z', '+00:00')).timestamp(),
                'last_modified_ts': dt.datetime.fromisoformat(row['last_modified'].replace('Z', '+00:00')).timestamp(),
                'vuln_status': row['vuln_status'], 'base_score': float(data['baseScore']),
                'severity': data.get('baseSeverity', ''), 'cvss_version': data['version'],
                'attack_vector': 'NETWORK', 'cvss_source': metric.get('source', ''), 'language': 'en'}
        def emit(kind, entity, field, text, url=''):
            prefix = f'{cve} | {kind} | {entity} | {field}\n'
            chunks = split_text(text, prefix, tokenizer)
            for i, doc in enumerate(chunks):
                m = dict(meta, content_type=kind, entity_id=str(entity), field=field,
                         chunk_index=i, content_hash=hashlib.sha256(doc.encode()).hexdigest())
                if url:
                    m['source_url'] = url
                records.append({'id': f'{cve}:{kind}:{entity}:{field}:{i:05d}', 'document': doc, 'metadata': m})
            if chunks:
                coverage[kind] += 1
        descriptions = [x['value'] for x in json.loads(row['descriptions_json']) if x.get('lang') == 'en' and x.get('value', '').strip()]
        if not descriptions:
            raise ValueError(f'{cve} no tiene descripción inglesa')
        for i, text in enumerate(dict.fromkeys(descriptions)):
            emit('nvd', cve, f'description_{i}', text, source_url)
        capecs = {}
        cwes = json.loads(row['cwes_json'])
        if cwes: coverage['cve_with_cwe'] += 1
        for cwe in cwes:
            if not cwe.get('context_available'):
                missing.append({'cve_id': cve, 'cwe_id': cwe['id']})
            for field in ('name', 'description', 'extended_description', 'potential_mitigations'):
                emit('cwe', cwe['id'], field, cwe.get(field), f"https://cwe.mitre.org/data/definitions/{cwe['id'].split('-')[1]}.html")
            for capec in cwe.get('capec', cwe.get('capecs', [])):
                key = str(capec['id'])
                if key in capecs and capecs[key] != capec:
                    raise ValueError('CAPEC incompatible en catálogo')
                capecs[key] = capec
        if capecs: coverage['cve_with_capec'] += 1
        for key, capec in sorted(capecs.items()):
            for field in ('name', 'description', 'execution_flow', 'prerequisites', 'consequences'):
                emit('capec', key, field, capec.get(field), f'https://capec.mitre.org/data/definitions/{key}.html')
        for i, item in enumerate(cpemap[cve]):
            text = '\n'.join(f'{k}: {v}' for k, v in item.items() if k != 'cve_id' and v is not None)
            emit('cpe', str(i), 'affected_product', text, source_url)
        exploits = json.loads(row['exploits_json'])
        if exploits: coverage['cve_with_exploit'] += 1
        for exploit in exploits:
            emit('exploit', str(exploit['id']), 'description', exploit['description'], exploit['url'])
    if len({r['id'] for r in records}) != len(records):
        raise ValueError('IDs repetidos')
    run.mkdir(parents=True, exist_ok=True)
    documents_hash = digest(records)
    path = run / 'documentos.json.gz'
    if not path.exists():
        temp = path.with_suffix('.tmp')
        with gzip.open(temp, 'wt', encoding='utf-8') as f: json.dump(records, f, ensure_ascii=False)
        temp.replace(path)
    else:
        with gzip.open(path, 'rt', encoding='utf-8') as f:
            if digest(json.load(f)) != documents_hash: raise ValueError('Caché documental inválida')
    manifest = dict(spec, run_id=run_id, documents_hash=documents_hash, document_count=len(records),
                    cve_count=len(rows), years=dict(collections.Counter(r['published'][:4] for r in rows)),
                    chunks_by_type=dict(collections.Counter(r['metadata']['content_type'] for r in records)),
                    coverage=dict(coverage), missing_cwe=missing, sqlite_file_hash=file_hash(db),
                    sqlite_path=str(Path(db).resolve()))
    save_json(run / 'manifiesto.json', manifest)
    return records, manifest, run


def embeddings(records, run, model, progress=print, tokenizer=None):
    path = Path(run) / 'embeddings.npy'; checkpoint = Path(run) / 'embeddings_progreso.json'
    n = len(records)
    if path.exists():
        array = np.load(path, mmap_mode='r+')
        if array.shape != (n, 384): raise ValueError('Forma de embeddings inválida')
        done = json.loads(checkpoint.read_text())['completed'] if checkpoint.exists() else 0
    else:
        array = np.lib.format.open_memmap(path, mode='w+', dtype='float32', shape=(n, 384)); done = 0
    if not 0 <= done <= n: raise ValueError('Checkpoint de embeddings inválido')
    if tokenizer is None:
        from tokenizers import Tokenizer
        tokenizer = Tokenizer.from_str(model.tokenizer.to_str())
        tokenizer.no_padding(); tokenizer.no_truncation()
    order_path = Path(run) / 'embeddings_orden.npy'
    lengths = np.zeros(n, dtype='int32')
    if order_path.exists():
        order = np.load(order_path)
        if order.shape != (n,) or not np.array_equal(np.sort(order), np.arange(n)):
            raise ValueError('Orden de embeddings inválido')
    else:
        # Conserva un checkpoint secuencial anterior y agrupa el resto por longitud.
        for i in range(done, n): lengths[i] = len(tokenizer.encode(records[i]['document']).ids)
        order = np.asarray(list(range(done)) + sorted(range(done, n), key=lambda i: (lengths[i], i)))
        temp = order_path.with_suffix('.tmp')
        with open(temp, 'wb') as f: np.save(f, order)
        temp.replace(order_path)
    order_hash = file_hash(order_path)
    if checkpoint.exists():
        recorded_hash = json.loads(checkpoint.read_text()).get('order_sha256')
        if recorded_hash and recorded_hash != order_hash: raise ValueError('Orden de reanudación cambiado')
    for i in order[done:]:
        if not lengths[i]: lengths[i] = len(tokenizer.encode(records[i]['document']).ids)
        if lengths[i] > MAX_TOKENS: raise ValueError('Documento excede el límite de tokens')
    for start in range(done, n, 32):
        end = min(n, start + 32)
        indices = order[start:end]
        # El padding solo cubre el mayor documento del lote; no altera su texto.
        model.tokenizer.enable_padding(pad_id=0, pad_token='[PAD]', length=int(max(lengths[indices])))
        vectors = np.asarray(model([records[i]['document'] for i in indices]), dtype='float32')
        if vectors.shape != (end-start, 384) or not np.isfinite(vectors).all(): raise ValueError('Embeddings inválidos')
        array[indices] = vectors; array.flush()
        save_json(checkpoint, {'completed': end, 'order_sha256': order_hash})
        if start == done or end == n or (start // 32) % 20 == 0: progress(f'Embeddings: {end}/{n}', flush=True)
    if not np.isfinite(array).all() or np.any(np.linalg.norm(array, axis=1) == 0): raise ValueError('Vectores nulos/no finitos')
    model.tokenizer.enable_padding(pad_id=0, pad_token='[PAD]', length=256)
    save_json(Path(run) / 'embeddings_verificados.json', {'sha256': file_hash(path), 'count': n, 'dimension': 384})
    return array


def names(client):
    return {c.name for c in client.list_collections()}


def backup(client, name, out):
    collection = client.get_collection(name, embedding_function=None)
    expected = collection.count(); records = []
    for start in range(0, expected, 100):
        page = collection.get(limit=100, offset=start, include=['documents', 'metadatas', 'embeddings'])
        for i, id_ in enumerate(page['ids']):
            vector = page['embeddings'][i].tolist() if page['embeddings'] is not None else None
            records.append({'id': id_, 'document': page['documents'][i], 'metadata': page['metadatas'][i], 'embedding': vector})
    if len(records) != expected or len({r['id'] for r in records}) != expected or collection.count() != expected:
        raise ValueError('Respaldo incompleto o colección cambiada')
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    directory = Path(out) / 'respaldos' / f'{name}_{stamp}'; directory.mkdir(parents=True)
    payload = {'name': name, 'metadata': collection.metadata, 'configuration': collection.configuration, 'records': records}
    path = directory / 'coleccion.json.gz'
    with gzip.open(path, 'wt', encoding='utf-8') as f: json.dump(payload, f, ensure_ascii=False)
    info = {'created_at': utc(), 'name': name, 'count': expected, 'sha256': file_hash(path), 'payload_hash': digest(payload)}
    save_json(directory / 'manifiesto.json', info)
    verify_backup(directory)
    return str(directory)


def verify_backup(directory):
    directory = Path(directory); info = json.loads((directory / 'manifiesto.json').read_text())
    path = directory / 'coleccion.json.gz'
    if file_hash(path) != info['sha256']: raise ValueError('Hash del respaldo inválido')
    with gzip.open(path, 'rt', encoding='utf-8') as f: data = json.load(f)
    if digest(data) != info['payload_hash'] or len(data['records']) != info['count']:
        raise ValueError('Contenido del respaldo inválido')
    if len({r['id'] for r in data['records']}) != info['count']: raise ValueError('IDs del respaldo duplicados')
    return data


def restore(client, directory, target=None):
    data = verify_backup(directory); name = target or data['name']
    if name in names(client): raise ValueError('Restauración requiere nombre libre')
    configuration = {'hnsw': data['configuration']['hnsw']} if data['configuration'].get('hnsw') else None
    collection = client.create_collection(name=name, metadata=data['metadata'], configuration=configuration, embedding_function=None)
    for start in range(0, len(data['records']), 100):
        batch = data['records'][start:start+100]
        kwargs = {'ids': [r['id'] for r in batch], 'embeddings': [r['embedding'] for r in batch]}
        for field, key in [('document', 'documents'), ('metadata', 'metadatas')]:
            if any(r[field] is not None for r in batch): kwargs[key] = [r[field] for r in batch]
        collection.upsert(**kwargs)
    if collection.count() != len(data['records']): raise ValueError('Restauración incompleta')
    return collection


def replace_and_load(client, records, vectors, manifest, run, out, old=OLD_COLLECTION, target=COLLECTION, progress=print):
    if manifest.get('sqlite_path') and file_hash(manifest['sqlite_path']) != manifest['sqlite_file_hash']:
        raise ValueError('SQLite cambió después de preparar documentos')
    if len(records) != manifest['document_count'] or digest(records) != manifest['documents_hash']:
        raise ValueError('Documentos no corresponden al manifiesto')
    if vectors.shape != (len(records), 384) or not np.isfinite(vectors).all() or np.any(np.linalg.norm(vectors, axis=1) == 0):
        raise ValueError('Vectores no preparados; no se elimina ninguna colección')
    verification = json.loads((Path(run) / 'embeddings_verificados.json').read_text())
    if verification['sha256'] != file_hash(Path(run) / 'embeddings.npy'):
        raise ValueError('Hash de embeddings inválido')
    if not np.array_equal(np.load(Path(run) / 'embeddings.npy', mmap_mode='r'), vectors):
        raise ValueError('Los vectores recibidos difieren de los verificados')
    state_path = Path(run) / 'estado.json'
    state = json.loads(state_path.read_text()) if state_path.exists() else {'state': 'preparado', 'completed': 0, 'backups': []}
    def persist(label):
        state.update(state=label, updated_at=utc()); save_json(state_path, state)
    client.heartbeat()
    if old == target: raise ValueError('Nombres anterior y destino deben diferir')
    if old in names(client):
        state['backups'].append(backup(client, old, out)); persist('respaldado')
        client.delete_collection(old)
        if old in names(client): raise ValueError('La colección anterior todavía existe')
    persist('anterior_eliminado')
    if target in names(client):
        collection = client.get_collection(target, embedding_function=None)
        if (collection.metadata or {}).get('run_id') != manifest['run_id']:
            state['backups'].append(backup(client, target, out)); persist('respaldado')
            client.delete_collection(target); state['completed'] = 0; collection = None
        else:
            if collection.count() > len(records): raise ValueError('Destino contiene registros inesperados')
            if collection.count() < state['completed']: state['completed'] = 0
    else: collection = None; state['completed'] = 0
    if collection is None:
        collection = client.create_collection(target, embedding_function=None,
                        metadata={'run_id': manifest['run_id'], 'embedding_model': MODEL, 'dimension': 384, 'status': 'loading'},
                        configuration={'hnsw': {'space': 'cosine'}})
    persist('cargando')
    for start in range(state['completed'], len(records), 100):
        batch = records[start:start+100]; end = start+len(batch)
        collection.upsert(ids=[r['id'] for r in batch], documents=[r['document'] for r in batch],
                          metadatas=[r['metadata'] for r in batch], embeddings=np.asarray(vectors[start:end]))
        state['completed'] = end; persist('cargando')
        if start % 1000 == 0 or end == len(records): progress(f'Chroma: {end}/{len(records)}', flush=True)
    return collection, state


def validate(client, collection, records, vectors, manifest, run, db, tokenizer, old=OLD_COLLECTION):
    try:
        return _validate(client, collection, records, vectors, manifest, run, db, tokenizer, old)
    except BaseException:
        # Una validación fallida obliga a verificar/reponer todos los lotes al reanudar.
        path = Path(run) / 'estado.json'
        if path.exists():
            state = json.loads(path.read_text())
            state.update(state='cargando', completed=0, updated_at=utc())
            save_json(path, state)
        raise


def _validate(client, collection, records, vectors, manifest, run, db, tokenizer, old):
    if old in names(client): raise ValueError('Colección anterior todavía presente')
    if collection.count() != len(records): raise ValueError('Conteo de documentos incorrecto')
    if collection.configuration['hnsw']['space'] != 'cosine': raise ValueError('Distancia incorrecta')
    found = {}; max_tokens = 0
    for start in range(0, len(records), 100):
        batch = records[start:start+100]; page = collection.get(ids=[r['id'] for r in batch], include=['documents','metadatas','embeddings'])
        by_id = {id_: i for i, id_ in enumerate(page['ids'])}
        if set(by_id) != {r['id'] for r in batch}: raise ValueError('IDs faltantes')
        for j, record in enumerate(batch):
            i = by_id[record['id']]; document = page['documents'][i]; meta = page['metadatas'][i]
            if document != record['document'] or meta != record['metadata']: raise ValueError('Documento o metadatos distintos')
            v = np.asarray(page['embeddings'][i])
            if v.shape != (384,) or not np.isfinite(v).all() or not np.allclose(v, vectors[start+j], atol=1e-6): raise ValueError('Vector incorrecto')
            length = len(tokenizer.encode(document).ids); max_tokens = max(max_tokens, length)
            if length > MAX_TOKENS: raise ValueError('Texto truncable')
            found[meta['cve_id']] = meta['published_year']
    rows, cpes = catalogue(db)
    if set(found) != {r['id'] for r in rows}: raise ValueError('Cobertura de CVE incorrecta')
    if collections.Counter(found.values()) != {2023:250,2024:250,2025:250,2026:250}: raise ValueError('Cuota anual incorrecta')
    if digest({'rows': rows, 'cpes': cpes}) != manifest['catalogue_hash'] or file_hash(db) != manifest['sqlite_file_hash']:
        raise ValueError('SQLite cambió durante la carga')
    state = json.loads((Path(run) / 'estado.json').read_text()); state.update(state='validado', updated_at=utc()); save_json(Path(run) / 'estado.json', state)
    collection.modify(metadata=dict(collection.metadata, status='validated'))
    report = dict(manifest, validated_at=utc(), collection=collection.name, previous_collection_absent=True,
                  max_document_tokens=max_tokens, integrity_check='ok', foreign_key_errors=[], backups=state['backups'],
                  embeddings_sha256=file_hash(Path(run) / 'embeddings.npy'),
                  documents_file_sha256=file_hash(Path(run) / 'documentos.json.gz'))
    save_json(Path(run) / 'informe.json', report); save_json(Path(run).parents[1] / 'informe_indexacion.json', report)
    return report


def retrieve(db, cve_ids):
    with sqlite3.connect(f'file:{Path(db).resolve()}?mode=ro', uri=True) as c:
        c.row_factory = sqlite3.Row
        return [dict(c.execute('SELECT * FROM VW_CVE_CATALOGO WHERE id=?', (id_,)).fetchone()) for id_ in dict.fromkeys(cve_ids)]
