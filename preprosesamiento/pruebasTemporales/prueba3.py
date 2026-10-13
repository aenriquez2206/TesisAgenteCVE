import chromadb

client = chromadb.HttpClient(
    host="localhost",
    port=8001
)

collection = client.get_collection(
    name="catalogo_cve_2023_2026"
)

datos = collection.get(
    limit=1,
    include=["embeddings"]
)

print(datos["embeddings"][0])