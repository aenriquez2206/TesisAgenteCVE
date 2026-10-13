"""Busca fragmentos y recupera el catálogo SQLite con el mismo modelo de indexación."""
from pathlib import Path
import sys
import chromadb

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'preprosesamiento' / 'chroma'))
import indexacion as ix


def main():
    client = chromadb.HttpClient(host='localhost', port=8001)
    collection = client.get_collection(ix.COLLECTION, embedding_function=None)
    _, model, _ = ix.tokenizer_and_model()
    query = ' '.join(sys.argv[1:]) or 'Remote command injection vulnerability and mitigations'
    result = collection.query(query_embeddings=model([query]), n_results=5,
                              include=['documents', 'metadatas', 'distances'])
    ids = list(dict.fromkeys(m['cve_id'] for m in result['metadatas'][0]))
    contexts = ix.retrieve(ROOT / 'preprosesamiento' / 'sqlite' / 'catalogo.sqlite3', ids)
    print('Consulta:', query)
    for context in contexts:
        print('CVE:', context['id'], 'Publicado:', context['published'])
    for doc, meta, distance in zip(result['documents'][0], result['metadatas'][0], result['distances'][0]):
        print(meta['cve_id'], meta['content_type'], 'Distancia:', round(distance, 4))
        print(doc)


if __name__ == '__main__':
    main()
