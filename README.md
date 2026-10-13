# CVE Intelligence

Chat RAG local con React/TypeScript, FastAPI, ChromaDB y Docker Model Runner.
El navegador se comunica exclusivamente con la API del backend. Las conversaciones
se guardan en el navegador; el servidor no mantiene una base de conversaciones.

## Ejecutar con Docker

Requisitos: Docker Engine/Compose y Docker Model Runner con el modelo exacto
`ministral3:8B-Q4_K_M`. Su API debe estar disponible en el host, puerto 12434.

```bash
cp .env.example .env.chat
docker compose --env-file .env.chat up -d --build
docker compose ps
```

- Interfaz: http://localhost:5173 (puerto estricto).
- Backend: http://localhost:8000; OpenAPI: http://localhost:8000/docs.
- ChromaDB: http://localhost:8001; interfaz administrativa existente: http://localhost:8090.

Compose conserva `./chroma_data:/data`, la red y el servicio `chromadb-ui`.
El backend conecta a `chromadb:8000` y a
`model-runner.docker.internal:12434/engines/v1`. El navegador conecta a
`http://localhost:8000`. Las variables con sufijo `_DOCKER` distinguen las direcciones
internas de las direcciones de ejecución local; el backend recibe los nombres normales.
No se requiere nginx. Model Runner se reutiliza desde el host, no se instala desde Compose.

El repositorio anidado `chromadb-ui/` es opcional. Si no está presente, levantar solo
los servicios necesarios: `docker compose --env-file .env.chat up -d --build chromadb backend frontend`.

## Ejecutar localmente

Requisitos: Python 3.12, Node 22.12+ y npm. ChromaDB y Model Runner deben estar disponibles.
Las dependencias están fijadas en los manifiestos y el lockfile; no es necesario actualizarlas.

```bash
docker compose up -d chromadb
python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt
cp .env.example .env.chat
set -a
source .env.chat
set +a
PYTHONPATH=backend .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

En otra terminal, desde la raíz:

```bash
set -a
source .env.chat
set +a
cd frontend
npm ci
npm run dev
```

El backend lee variables del proceso; no carga automáticamente `.env`. El archivo
`.env` existente se conserva para preprocesamiento. `.env.chat` está ignorado por Git.
Si un entorno Python existente carece de pip, restaurarlo con
`.venv/bin/python -m ensurepip` antes de instalar dependencias.

## Configuración y datos

Consultar [`.env.example`](.env.example). Valores iniciales:

| Configuración | Valor |
|---|---|
| Colección / tenant / database | `catalogo_cve_2023_2026` / `default_tenant` / `default_database` |
| LLM | `ministral3:8B-Q4_K_M` |
| Embeddings | `sentence-transformers/all-MiniLM-L6-v2`, ONNX, CPU, 384 dimensiones normalizadas |
| Métrica / recuperación | Coseno / `TOP_K=8` |
| Contexto | `CONTEXT_CHARS=6000` |
| Salida preparación / respuesta / comparación | 120 / 220 / 350 tokens |
| Validación de colección / resolución del modelo | Cachés de 60 segundos |
| Timeouts LLM / Chroma / salud / embeddings | 120 / 15 / 5 / 30 segundos |
| CORS | `http://localhost:5173` |

Se verifican hashes del modelo ONNX y del tokenizador contra la ingesta existente.
Las consultas que exceden 256 tokens se rechazan antes de cualquier truncamiento.
La ingesta usó fragmentos de hasta 240 tokens con ese mismo modelo/tokenizador.
Cambiar un hash para omitir un error de compatibilidad no es una reparación válida.

El chat **solo lee** la colección: no crea ni borra colecciones, no hace upsert y no
regenera embeddings almacenados. Un clon sin datos requiere una copia privada de
`chroma_data/` obtenida con el servidor detenido. El chat no ejecuta automáticamente
los notebooks para suplir datos ausentes. El catálogo SQLite, las fuentes y notebooks
permanecen en [`preprosesamiento/`](preprosesamiento/README.md).

## Comportamiento y API

La interfaz abre en **Detección**, una simulación local de Nmap con tres hallazgos
ilustrativos. No contacta la IP ni ejecuta comandos. Las conversaciones desde esas
tarjetas usan respuestas predefinidas, aisladas por ejecución, objetivo y CVE; existen
solo en memoria hasta recargar. **Consultas** conserva el chat RAG, su historial local
y la evidencia recuperada.

`POST /api/chat` recibe `message`, `conversation_id` opcional e `history` con roles
`user`/`assistant`. Límites: 4 000 caracteres por mensaje, 10 entradas de historial,
12 000 caracteres de historial y 80 caracteres para el identificador de conversación.
Devuelve `answer`, `conversation_id`, `request_id`, `sources` y `trace`.

Las preguntas habituales con un CVE explícito se preparan mediante reglas locales
y consultas inglesas predefinidas. Los seguimientos con un único CVE inequívoco se
resuelven localmente; una referencia ambigua solicita aclaración. Las preguntas
libres, condiciones de producto/versión y comparaciones complejas conservan el
preparador LLM. El inglés independiente conserva sus palabras y un CVE aislado
hereda el idioma del último usuario o asume español. La preparación dispone de
120 tokens y un reintento; si se trunca, ese reintento permite hasta 350 tokens.
No se usa traducción externa ni se omiten controles de identificadores/versiones.

Las preguntas exactas de descripción y CVSS recuperan NVD por metadatos sin
embeddings. Las búsquedas semánticas conservan `TOP_K=8` y filtros `cve_id`. Las
lecturas complementarias se agrupan por CVE y tipos solicitados, con hasta tres
registros por tipo y cuatro operaciones simultáneas. Las comparaciones incluyen
evidencia de cada CVE disponible. Los objetos de colección se validan y reutilizan
durante 60 segundos; salud fuerza la comprobación completa. Los resultados se
deduplican y se limitan al presupuesto del contexto. `sources` contiene exactamente
los fragmentos usados, en el orden de las citas `[n]`; no representa todos los vecinos.
Las distancias coseno no son probabilidades ni porcentajes.

El modelo debe fundamentar sus afirmaciones y reconocer información ausente. Se
validan citas, identificadores y cifras tras cada intento de generación, con un solo
reintento. La pregunta del usuario no respalda puntuaciones CVSS. Estas comprobaciones
mecánicas **no garantizan veracidad semántica**: una cita válida puede acompañar una
inferencia incorrecta. Las decisiones deben contrastarse con las fuentes mostradas.

CVSS/severidad se responden mediante plantillas citadas usando solo metadatos NVD
del CVE solicitado; los valores ausentes se indican expresamente. Las preguntas
sobre presencia de registros también admiten una plantilla cuando la recuperación
no encontró el tipo solicitado y existe evidencia NVD del CVE. Las explicaciones
siguen usando el modelo, con 220 tokens o 350 para comparaciones y un único reintento.
La salida truncada nunca se publica. Los registros CWE/CAPEC se explican como
información genérica relacionada, separada de los mecanismos confirmados del CVE.

`trace` contiene idiomas, consulta inglesa, estados, cantidades, modelos y tiempos
por etapa, ruta, uso de plantilla, llamadas al modelo, reintentos y operaciones HTTP
de Chroma. `model_wait` y `validation` están incluidos en los tiempos de las etapas,
no deben sumarse otra vez al total. Sin fuentes o al usar una plantilla,
`generation_status=skipped`; las plantillas pueden incluir fuentes verificadas.
La interfaz permite elegir una respuesta y consultar su evidencia; no simula progreso
por etapas mientras espera la respuesta HTTP completa.

`GET /api/health` comprueba por separado servidor Chroma, colección, embeddings y modelo.
Devuelve 200 si el backend responde, incluso con dependencias no disponibles; deben
examinarse los estados y motivos. La comprobación de Chroma y colección puede consumir
hasta dos veces `HEALTH_TIMEOUT`; las demás comprobaciones se ejecutan en paralelo.

Errores: 422 entrada/referencia inválida; 503 dependencia o compatibilidad;
504 timeout; 502 preparación/generación inválida; 500 fallo inesperado; 499 cliente
desconectado. La desconexión cancela la generación pendiente para liberar el modelo.
Incluyen `request_id`, `code` y `message`. La ausencia de resultados devuelve 200.

## Logs y pruebas

La matriz de 60 casos de evaluación del agente y el informe resultante se describen
en [docs/validacion_agente.md](docs/validacion_agente.md).
La configuración del ejecutor, las mediciones de latencia y la comparación de
presupuestos de contexto se documentan en [docs/latencia_agente.md](docs/latencia_agente.md).

```bash
docker compose logs backend
PYTHONPATH=backend .venv/bin/python -m unittest discover -s backend/tests -v
.venv/bin/python -m unittest discover -s preprosesamiento/sqlite -p 'test_*.py' -v
.venv/bin/python -m unittest discover -s preprosesamiento/chroma -p 'test_*.py' -v
cd frontend
npm test
npm run build
```

Cada búsqueda y lectura complementaria registra inicio y fin/fallo correlacionados
con solicitud y conversación, límites, duración, resultados, IDs, distancias, fuentes
y resúmenes acotados. Preparación y generación registran sus propios estados; nunca
se registra razonamiento interno ni documentos completos. La consulta abreviada puede
contener texto del usuario: no introducir credenciales en el chat.

Los logs JSON se escriben a consola. Para conservación rotativa puede configurarse
el driver `local` de Docker (`max-size`, `max-file`) por servicio; no se activa una
segunda copia de logs por defecto. Los timeouts HTTP de Chroma se aplican mediante un
adaptador aislado para el cliente 1.5.9, que debe revisarse si se actualiza el SDK.

La referencia visual está en `docs/referencia/`; el inventario por archivo y la
comprobación histórica están en [`docs/inventario.json`](docs/inventario.json).
Consultar [`docs/validacion.md`](docs/validacion.md) para los resultados de aceptación.
Autenticación, streaming, proveedores cloud e historial en servidor quedan fuera del MVP.
