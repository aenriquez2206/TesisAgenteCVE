# Catálogo SQLite e indexación en ChromaDB

El flujo vigente es `cargar_catalogo.ipynb`: consulta la API NVD 2.0 y carga el
esquema relacional de `sqlite/catalogo.sqlite3`. Cada ejecución confirma una
muestra de **1.000 CVE: 250 por año de publicación de 2023 a 2026**, junto con los
catálogos completos de CWE, CAPEC y ExploitDB. La indexación posterior se ejecuta por separado con `indexar_chroma.ipynb`.

## Preparación

Desde la raíz del repositorio, usar Python 3.10+ y SQLite 3.38+ con funciones JSON:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r preprosesamiento/requirements.txt
```

Si el entorno existente no contiene pip, utilizar el pip del sistema:

```bash
python3 -m pip --python .venv install -r preprosesamiento/requirements.txt
```

La raíz debe contener `.env` con `API_KEY_NVD`. El código lee esa variable dentro
del cliente y la envía mediante el encabezado `apiKey`; nunca debe escribirse en
una celda, URL, informe o salida. El notebook de indexación no lee esta clave ni consulta NVD.

## Abrir o ejecutar el notebook

```bash
.venv/bin/python -m jupyterlab preprosesamiento/cargar_catalogo.ipynb
```

Ejecutar las celdas en orden con el kernel del mismo entorno. Para ejecutar y
persistir todas las salidas sin abrir un navegador:

```bash
.venv/bin/python preprosesamiento/sqlite/ejecutar_notebook.py
```

El ejecutor utiliza el Python con el que se lo invoca, no requiere registrar un
kernel global y guarda también el progreso si se interrumpe la ejecución.

El notebook muestra configuración, auditoría de fuentes, consulta NVD, selección
anual, transformación, sentencias INSERT, carga y validación. Las funciones
reutilizables están en `sqlite/carga_catalogo.py`; el esquema permanece en
`sqlite/schema.sql`, con siete tablas y dos vistas.

## Selección y reproducibilidad

- El año se calcula a partir de `published` en UTC, no del ID ni de `lastModified`.
- Se recorren todas las ventanas mensuales y páginas disponibles de cada año.
  Para 2026 se consulta únicamente hasta la fecha de corte de la descarga.
- Se admiten `Analyzed`/`Modified`, alguna descripción no vacía, alguna métrica
  CVSS 3.0 o 3.1 `NETWORK` y una referencia HTTP(S) con `Vendor Advisory`, o con
  `Exploit` hacia un repositorio concreto de GitHub/GitLab/Bitbucket o una página
  `exploit-db.com/exploits/{id}`. Otra métrica `LOCAL` no invalida una `NETWORK`.
- Se deduplican IDs conservando la observación con `lastModified` más reciente.
  Las diferencias con igual fecha se reportan y se desempatan por hash.
- La población elegible se ordena por ID. Cada año usa
  `random.Random(SEMILLA + año).sample(..., CUOTA_ANUAL)` sin reemplazo.
- `SEMILLA=42` y `CUOTA_ANUAL=250` son los valores entregados. Si falta una cuota,
  la base no se modifica y ningún otro año compensa el déficit.

`REFRESCAR_NVD=False` reutiliza o reanuda páginas de una descarga compatible,
conservando su fecha de corte. La caché guarda respuestas públicas comprimidas y
sus hashes, sin la clave. Para una descarga nueva, cambiar el valor a `True`;
para una nueva muestra de la misma población, cambiar únicamente `SEMILLA`.
Una descarga completa requiere recorrer el año entero antes de muestrear: no se
detiene al encontrar los primeros 250 elegibles.

Las peticiones son secuenciales, con seis segundos entre intentos, timeout y
hasta cinco intentos ante fallos transitorios. Se respeta `Retry-After`. Un error
permanente detiene el proceso y conserva la caché ya verificada para reanudar.

## Qué se carga

Los cuatro CSV originales y `NVDExample.json` están en `sqlite/fuentes/`, con sus
contenidos y hashes intactos. Los cinco CVE de NVDExample son exclusivamente una
fixture de prueba: no participan en la muestra descargada ni se insertan en ella.

Se cargan todos los CWE de hardware/software, los 559 CAPEC y los 46.698 exploits
únicos de los archivos entregados. Se añaden CWE con contexto NULL cuando sus IDs
se referencian pero no están en los CSV. Las asociaciones CVE–CWE, CAPEC–CWE y
exploit–CVE se almacenan como pares únicos, sin inventar relaciones.

Las fechas NVD se normalizan a UTC. Las descripciones, métricas, debilidades,
configuraciones y referencias seleccionadas se conservan íntegras como JSON.
Los campos compuestos de MITRE conservan su texto original. ExploitDB almacena
solo el ID y título; su enlace web se calcula al consultar. Los CVE de ExploitDB
no seleccionados se reportan, sin crear entidades NVD incompletas.

La carga respalda la base mediante `sqlite3.backup`, activa FK y sustituye el
contenido de las siete tablas dentro de una sola transacción. Se ejecuta commit
solo después de verificar cuotas, filas, asociaciones y vistas; cualquier fallo
provoca rollback. Repetir el notebook no acumula muestras antiguas.

## Resultados y consultas

- `sqlite/catalogo.sqlite3`: base poblada del esquema v1.
- `sqlite/salidas/seleccion_nvd.json`: fecha de corte, semilla, filtros, población,
  descartes e IDs de la muestra de cada año.
- `sqlite/salidas/informe_carga.json` y `.md`: conteos, hashes y cobertura final.
- `sqlite/salidas/cache_nvd/`: manifiesto y páginas comprimidas para reanudación.
- `sqlite/salidas/respaldos/`: copias consistentes anteriores a cada carga.
- `sqlite/consultas.sql`: consultas independientes con parámetros.

La validación requiere 1.000 filas en `NVD_CVE` y `VW_CVE_CATALOGO`, 250 por año,
`integrity_check=ok` y ningún error de FK. La vista del catálogo devuelve una
fila por CVE con sus CWE y CAPEC anidados y una lista independiente de exploits.
La vista CPE proyecta condiciones y rangos; la aplicabilidad exige interpretar
el árbol original de configuraciones.

## Pruebas y auditoría

```bash
.venv/bin/python -m unittest discover -s preprosesamiento/sqlite -p 'test_*.py' -v
.venv/bin/python preprosesamiento/sqlite/revisar_fuentes.py
```

Las pruebas usan HTTP simulado y bases temporales; no gastan solicitudes NVD ni
modifican la base entregada. Cubren filtros, límites, paginación, reanudación,
muestreo, duplicados, transacciones y rollback. El informe de fuentes identifica
los originales por hash; es independiente del informe de la carga actual.

El extractor anterior de los 1.000 registros hacia Chroma se retiró. Esta
limpieza de archivos se limita a `preprosesamiento`. El `.env` y la infraestructura
Chroma se conservan; la nueva indexación reemplaza por API únicamente las
colecciones indicadas en la siguiente sección.

## Indexar SQLite en ChromaDB

Chroma debe estar disponible en `localhost:8001` con el compose de la raíz:

```bash
docker compose up -d
.venv/bin/python preprosesamiento/chroma/ejecutar_notebook.py
```

También puede abrirse `preprosesamiento/indexar_chroma.ipynb` en JupyterLab y
seguir sus celdas en orden. La primera ejecución prepara todos los documentos y
vectores antes de respaldar y eliminar `nvd_cve_2023_2026`. Crea
`catalogo_cve_2023_2026` con distancia coseno; no cambia otras colecciones,
Docker, `.env`, fuentes ni SQLite. No descarga más CVE.

El modelo ONNX local `sentence-transformers/all-MiniLM-L6-v2` genera vectores de
384 dimensiones. Se mantienen descripciones inglesas y textos originales de
CWE, CAPEC, productos afectados y títulos de exploits asociados. Consultar en
inglés; no se traduce automáticamente. Se fragmenta cada campo con encabezado,
240 tokens como máximo y hasta 30 de solapamiento, medidos sin truncamiento.
No se indexa código de exploits ni se inventa contexto para CWE faltantes.
Solo se indexan entidades asociadas a los 1.000 CVE seleccionados; los restantes
catálogos continúan disponibles en SQLite. Los productos CPE son una proyección:
para evaluar aplicabilidad se consulta el árbol original de configuraciones.

`chroma/indexacion.py` contiene la transformación, respaldo, restauración,
reanudación, carga, validación y recuperación del catálogo. La carpeta
`chroma/salidas/` contiene:

- `respaldos/`: exportaciones completas de colecciones, configuración, vectores
  originales y manifiestos con hashes.
- `cargas/<hash>/`: documentos, embeddings, manifiesto, checkpoints e informe.
- `informe_indexacion.json`: informe de la última carga validada.

Los embeddings se calculan en lotes agrupados por longitud, con padding adaptado
y un orden persistido que conserva la relación entre documento y vector.
Los IDs son deterministas. Repetir una carga compatible no acumula documentos;
las interrupciones continúan desde el checkpoint. Una colección destino
incompatible se respalda antes de sustituirla. El estado `cargando` significa
que todavía no terminó la validación; no existe una transacción que abarque
Chroma y SQLite. Durante el reemplazo, no ejecutar otros escritores sobre estas
colecciones ni modificar el catálogo SQLite. Si la carga falla, conservar las
salidas y volver a ejecutar el notebook.

Para restaurar un respaldo, desde una celda ya configurada:

```python
restaurada = ix.restore(client, ruta_respaldo, target="catalogo_restaurado")
```

El nombre destino debe estar libre. La restauración conserva la configuración,
los documentos, metadatos y vectores originales; no vuelve a calcular embeddings.
La interfaz del puerto 8090 puede mostrar la nueva colección. Para una consulta:

```bash
.venv/bin/python extracionPrubea.py "Command injection vulnerability and mitigations"
.venv/bin/python -m unittest discover -s preprosesamiento/chroma -p 'test_*.py' -v
```

El lector y el notebook usan el mismo modelo y recuperan el contexto completo
mediante `cve_id` desde `VW_CVE_CATALOGO`.
