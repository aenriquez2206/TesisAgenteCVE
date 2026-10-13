import chromadb

client = chromadb.HttpClient(
    host="localhost",
    port=8001
)

collection = client.get_collection(
    name="catalogo_cve_2023_2026"
)

print(collection.count())