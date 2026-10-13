import chromadb

client = chromadb.HttpClient(
    host="localhost",
    port=8001
)

collection = client.get_collection(
    name="catalogo_cve_2023_2026"
)

datos = collection.get(
    limit=10,
    include=[
        "documents",
        "metadatas",
        "embeddings"
    ]
)

print("IDs:", datos["ids"])
print("Cantidad embeddings:", len(datos["embeddings"]))

if len(datos["embeddings"]) > 0:
    print("Dimensión:", len(datos["embeddings"][0]))
    print("Primer vector:", datos["embeddings"][0][:10])