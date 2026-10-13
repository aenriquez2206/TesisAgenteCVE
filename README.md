# CVE Intelligence

Chat RAG local para consultar la colección existente de CVE. La aplicación muestra la respuesta del modelo local junto con los fragmentos concretos recuperados de ChromaDB. La interfaz usa React/Vite y el backend FastAPI.

## Requisitos

- Docker Engine y Docker Compose para ChromaDB y los servicios de la aplicación.
- Docker Model Runner ya instalado con `ministral3:8B-Q4_K_M`. La API del modelo se consulta en `http://localhost:12434/engines/v1/models`.
- Para ejecución sin contenedores: Python 3.12, Node 22.12+ y npm.

La colección existente es `catalogo_cve_2023_2026`, con embeddings ONNX `sentence-transformers/all-MiniLM-L6-v2` de 384 dimensiones. El chat solo lee ChromaDB. La base SQLite y los notebooks están en [`preprosesamiento/`](preprosesamiento/README.md).

**Los datos no se publican en GitHub.** Un clon nuevo necesita una colección Chroma local para responder consultas: copie `chroma_data/` por un canal privado desde la máquina original, o ejecute los notebooks de preprocesamiento para crearla. El catálogo `preprosesamiento/sqlite/catalogo.sqlite3` también se conserva localmente y se puede regenerar. Sin estos datos, la interfaz y el backend arrancan, pero `/api/health` indicará que la colección no está disponible.

## Ejecutar con Docker Compose

```bash
docker compose up -d --build
docker compose ps
```

Abrir `http://localhost:5173`. API: `http://localhost:8000`; documentación: `http://localhost:8000/docs`; ChromaDB: `localhost:8001`. `docker compose logs backend` muestra JSON de cada recuperación.

Compose conserva el bind mount `./chroma_data:/data` y reutiliza Docker Model Runner instalado en el host. En Linux, el backend accede a él mediante `model-runner.docker.internal:12434` y `host-gateway`. El frontend usa la URL pública del backend; dentro de Docker, el backend accede a Chroma por `chromadb:8000`.

## Ejecutar sin Docker

Levantar Chroma con `docker compose up -d chromadb` y comprobar que Docker Model Runner esté disponible. Después:

```bash
python3 -m venv .venv
python3 -m pip --python .venv install -r backend/requirements.txt
PYTHONPATH=backend .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

En otra terminal:

```bash
cd frontend
npm ci
npm run dev
```

Las variables admitidas están en [`.env.example`](.env.example). FastAPI usa variables del proceso; `.env` en la raíz se conserva para el cliente NVD de preprocesamiento y no se copia a los contenedores del chat.

## Comprobar

```bash
curl http://localhost:8000/api/health
curl -H 'Content-Type: application/json' -d '{"message":"What is CVE-2023-27849?"}' http://localhost:8000/api/chat
.venv/bin/python -m unittest discover -s preprosesamiento/sqlite -p 'test_*.py' -v
.venv/bin/python -m unittest discover -s preprosesamiento/chroma -p 'test_*.py' -v
PYTHONPATH=backend .venv/bin/python -m unittest discover -s backend/tests -p 'test_*.py' -v
cd frontend && npm run build
```

El historial se guarda únicamente en el navegador. La vista de evidencia enseña los datos disponibles en los fragmentos recuperados; la distancia coseno se muestra como distancia, nunca como porcentaje. El HTML de referencia está en [`docs/referencia/`](docs/referencia/cve-intelligence.html). El inventario anterior al traslado está en [`migration-manifest.json`](migration-manifest.json).
