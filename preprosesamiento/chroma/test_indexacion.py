"""Pruebas aisladas: no requieren un servidor ni eliminan colecciones reales."""
import copy
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
import numpy as np
import indexacion as ix


class Tokens:
    def encode(self, text, add_special_tokens=True):
        offsets = [m.span() for m in re.finditer(r'\S+', text)]
        return type('Encoded', (), {'ids': list(range(len(offsets) + (2 if add_special_tokens else 0))), 'offsets': offsets})()
    def to_str(self): return 'test-tokenizer'


class Collection:
    def __init__(self, name, metadata=None, configuration=None):
        self.name=name; self.metadata=metadata; self.configuration=configuration or {'hnsw': {'space':'cosine'}}; self.rows={}; self.fail=False
    def count(self): return len(self.rows)
    def upsert(self, ids, embeddings, documents=None, metadatas=None):
        if self.fail: self.fail=False; raise RuntimeError('interrupción simulada')
        for i,k in enumerate(ids): self.rows[k]={'id':k, 'embedding':np.asarray(embeddings[i]),'document':documents[i] if documents else None,'metadata':metadatas[i] if metadatas else None}
    def get(self, ids=None, limit=None, offset=0, include=None):
        keys=list(self.rows) if ids is None else [i for i in ids if i in self.rows]
        if ids is None: keys=keys[offset:offset+limit]
        return {'ids':keys,'documents':[self.rows[k]['document'] for k in keys],
                'metadatas':[self.rows[k]['metadata'] for k in keys],
                'embeddings':np.asarray([self.rows[k]['embedding'] for k in keys])}
    def modify(self, metadata): self.metadata=metadata


class Client:
    def __init__(self): self.collections={}; self.deleted=[]
    def heartbeat(self): return 1
    def list_collections(self): return list(self.collections.values())
    def get_collection(self, name, **kwargs): return self.collections[name]
    def create_collection(self,name,metadata=None,configuration=None,**kwargs):
        c=Collection(name,metadata,configuration); self.collections[name]=c; return c
    def delete_collection(self,name): self.deleted.append(name); del self.collections[name]


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.out=Path(self.temp.name); self.run=self.out/'run'; self.run.mkdir(); self.client=Client()
        self.records=[{'id':str(i),'document':f'document {i}','metadata':{'cve_id':str(i)}} for i in range(205)]
        self.vectors=np.ones((205,384),dtype='float32'); np.save(self.run/'embeddings.npy',self.vectors)
        ix.save_json(self.run/'embeddings_verificados.json',{'sha256':ix.file_hash(self.run/'embeddings.npy')})
        self.manifest={'run_id':'test-run','document_count':205,'documents_hash':ix.digest(self.records)}
    def add(self,name):
        c=self.client.create_collection(name,metadata={'original':True},configuration={'hnsw':{'space':'l2'}})
        c.upsert(ids=['old'],documents=['old doc'],metadatas=[{'source':'old'}],embeddings=[np.ones(384)])
        return c
    def load(self):
        return ix.replace_and_load(self.client,self.records,self.vectors,self.manifest,self.run,self.out,progress=lambda *a,**k:None)
    def test_chunk_original_text_and_limit(self):
        text='  '+ ' '.join(f'Token{i}' for i in range(1200))+'  '
        chunks=ix.split_text(text,'CVE | field\n',Tokens())
        self.assertGreater(len(chunks),1)
        self.assertTrue(all(len(Tokens().encode(c).ids)<=240 for c in chunks))
        for token in text.split(): self.assertTrue(any(token in c for c in chunks))
        self.assertTrue(chunks[0].endswith(' ') and chunks[-1].endswith('  '))
        self.assertEqual(chunks,ix.split_text(text,'CVE | field\n',Tokens()))
    def test_metric_network_priority(self):
        local={'type':'Primary','source':'a','cvssData':{'attackVector':'LOCAL','baseScore':10,'version':'3.1'}}
        network={'type':'Secondary','source':'z','cvssData':{'attackVector':'NETWORK','baseScore':8,'version':'3.0'}}
        self.assertEqual(ix.network_metric({'cvssMetricV31':[local],'cvssMetricV30':[network]}),network)
        primary=copy.deepcopy(network); primary['type']='Primary'
        self.assertEqual(ix.network_metric({'cvssMetricV30':[network,primary]}),primary)
        with self.assertRaises(ValueError): ix.network_metric({'cvssMetricV31':[local]})
    def test_backup_restore_and_corruption(self):
        original=self.add('original'); directory=ix.backup(self.client,'original',self.out)
        restored=ix.restore(self.client,directory,target='restored')
        self.assertEqual(restored.metadata,original.metadata)
        self.assertEqual(restored.configuration,original.configuration)
        self.assertEqual(restored.rows['old']['document'],'old doc')
        np.testing.assert_array_equal(restored.rows['old']['embedding'],original.rows['old']['embedding'])
        with self.assertRaises(ValueError): ix.restore(self.client,directory,target='original')
        with open(Path(directory)/'coleccion.json.gz','ab') as f:f.write(b'corruption')
        with self.assertRaises(ValueError):ix.verify_backup(directory)
    def test_delete_limited_and_rerun(self):
        self.add(ix.OLD_COLLECTION); untouched=self.add('another')
        c,state=self.load()
        self.assertEqual(c.count(),205); self.assertEqual(self.client.deleted,[ix.OLD_COLLECTION])
        self.assertIs(self.client.collections['another'],untouched)
        self.assertEqual(ix.verify_backup(state['backups'][0])['records'][0]['id'],'old')
        c,state=self.load(); self.assertEqual(c.count(),205); self.assertEqual(len(self.client.deleted),1)
    def test_no_delete_on_bad_vectors_or_backup_failure(self):
        self.add(ix.OLD_COLLECTION); self.vectors[0,0]=np.nan
        with self.assertRaises(ValueError):self.load()
        self.assertEqual(self.client.deleted,[])
        self.vectors[0,0]=1
        with patch.object(ix,'backup',side_effect=ValueError('backup failed')):
            with self.assertRaises(ValueError):self.load()
        self.assertEqual(self.client.deleted,[])
    def test_incompatible_target_backed_up(self):
        self.add(ix.COLLECTION); c,state=self.load()
        self.assertEqual(c.count(),205);self.assertEqual(self.client.deleted,[ix.COLLECTION])
        self.assertEqual(ix.verify_backup(state['backups'][0])['metadata'],{'original':True})
    def test_interrupt_resume(self):
        c=self.client.create_collection(ix.COLLECTION,metadata={'run_id':'test-run'}); c.fail=True
        with self.assertRaises(RuntimeError):self.load()
        state=json.loads((self.run/'estado.json').read_text());self.assertEqual(state['state'],'cargando')
        self.assertEqual(state['completed'],0)
        c,state=self.load(); self.assertEqual(c.count(),205)
        # Simulate acknowledged first batch and retry second batch after interruption.
        state['completed']=100;ix.save_json(self.run/'estado.json',state)
        c,state=self.load();self.assertEqual(c.count(),205)
        self.assertEqual(self.client.deleted,[])
    def test_capec_dedup_missing_context_scalar_metadata(self):
        capec={'id':1,'name':'Pattern','description':'Attack description','execution_flow':'steps','prerequisites':None,'consequences':None}
        row={'id':'CVE-2023-1000','published':'2023-01-01T00:00:00.000Z','last_modified':'2023-01-02T00:00:00.000Z','vuln_status':'Analyzed',
             'metrics_json':json.dumps({'cvssMetricV31':[{'source':'a','type':'Primary','cvssData':{'version':'3.1','attackVector':'NETWORK','baseScore':9.8,'baseSeverity':'CRITICAL'}}]}),
             'references_json':'[{"url":"https://github.com/vendor/project","tags":["Exploit"]}]','descriptions_json':'[{"lang":"en","value":"A description"}]',
             'cwes_json':json.dumps([{'id':'CWE-1','context_available':True,'name':'Weakness','capec':[capec]}, {'id':'CWE-2','context_available':False,'capec':[capec]}]),'exploits_json':'[]'}
        db=self.out/'db';db.write_text('fake')
        with patch.object(ix,'catalogue',return_value=([row],[])):
            records,m,run=ix.prepare(db,self.out,Tokens(),'modelhash')
            r2,m2,_=ix.prepare(db,self.out,Tokens(),'modelhash')
        self.assertEqual(records,r2);self.assertEqual(m['run_id'],m2['run_id'])
        self.assertEqual(sum(r['metadata']['content_type']=='capec' for r in records),3)
        self.assertEqual(m['missing_cwe'],[{'cve_id':'CVE-2023-1000','cwe_id':'CWE-2'}])
        self.assertTrue(all(isinstance(v,(str,int,float,bool)) for r in records for v in r['metadata'].values()))
        self.assertEqual(next(r['metadata']['source_url'] for r in records if r['metadata']['content_type']=='nvd'),
                         'https://github.com/vendor/project')
    def test_validate_rejects_changed_document(self):
        rows=[{'id':f'CVE-{year}-{i:04d}', 'published':f'{year}-01-01T00:00:00.000Z'} for year in range(2023,2027) for i in range(250)]
        records=[{'id':r['id'], 'document':'Original source text', 'metadata':{'cve_id':r['id'],'published_year':int(r['published'][:4])}} for r in rows]
        vectors=np.ones((1000,384),dtype='float32')
        c=self.client.create_collection(ix.COLLECTION, metadata={'run_id':'test'})
        c.upsert(ids=[r['id'] for r in records], documents=[r['document'] for r in records],
                 metadatas=[r['metadata'] for r in records], embeddings=vectors)
        manifest={'catalogue_hash':ix.digest({'rows':rows,'cpes':[]})}
        db=self.out/'db'; db.write_text('source');manifest['sqlite_file_hash']=ix.file_hash(db)
        ix.save_json(self.run/'estado.json',{'state':'cargando','completed':1000,'backups':[]})
        np.save(self.run/'embeddings.npy',vectors)
        (self.run/'documentos.json.gz').write_bytes(b'prepared documents')
        c.rows[records[0]['id']]['document']='Changed source text'
        with patch.object(ix,'catalogue',return_value=(rows,[])):
            with self.assertRaises(ValueError):ix.validate(self.client,c,records,vectors,manifest,self.run,db,Tokens())
            self.assertEqual(json.loads((self.run/'estado.json').read_text())['completed'],0)
            c.rows[records[0]['id']]['document']=records[0]['document']
            report=ix.validate(self.client,c,records,vectors,manifest,self.run,db,Tokens())
        self.assertEqual(report['integrity_check'],'ok')
        self.assertEqual(json.loads((self.run/'estado.json').read_text())['state'],'validado')

    def test_embedding_resume_sorted_batches_preserves_ids(self):
        class Padding:
            def enable_padding(self, **kwargs): pass
        class Model:
            tokenizer=Padding()
            calls=0
            fail=True
            def __call__(self, docs):
                self.calls+=1
                if self.fail and self.calls==2: raise RuntimeError('interrupted')
                return np.asarray([np.full(384,int(doc.split()[1])+1,dtype='float32') for doc in docs])
        records=[dict(r,document=r['document']+' long'*((205-i)%15)) for i,r in enumerate(self.records)]
        model=Model()
        with self.assertRaises(RuntimeError):ix.embeddings(records,self.run,model,tokenizer=Tokens(),progress=lambda *a,**k:None)
        state=json.loads((self.run/'embeddings_progreso.json').read_text())
        self.assertEqual(state['completed'],32)
        order=np.load(self.run/'embeddings_orden.npy');self.assertFalse(np.array_equal(order,np.arange(205)))
        model.fail=False
        result=ix.embeddings(records,self.run,model,tokenizer=Tokens(),progress=lambda *a,**k:None)
        for i in range(205):np.testing.assert_array_equal(result[i],np.full(384,i+1))
        result2=ix.embeddings(records,self.run,model,tokenizer=Tokens(),progress=lambda *a,**k:None)
        np.testing.assert_array_equal(result,result2)

    def test_sqlite_hash_unchanged_readonly(self):
        db=Path(__file__).resolve().parents[1]/'sqlite'/'catalogo.sqlite3'
        if not db.exists():
            self.skipTest('El catálogo SQLite local no se publica en GitHub')
        before=ix.file_hash(db);rows,cpes=ix.catalogue(db)
        self.assertEqual(len(rows),1000);self.assertEqual(ix.file_hash(db),before)


if __name__=='__main__':unittest.main()
