# Latencia del agente CVE

Configuración de aplicación: `TOP_K=8`, contexto de 6 000 caracteres, preparación
inicial de 120 tokens, respuesta de 220 y comparación de 350. Las reglas locales
cubren preguntas habituales con un CVE y comparaciones simples de dos CVE; las
condiciones adicionales conservan el preparador LLM. No se almacenan respuestas
finales en caché.

## Resultados medidos, 13 de octubre de 2026

Se ejecutaron los mismos 60 casos antes y después, con cargador original y modo de
rendimiento. Ambos informes usan Ministral 8B, contexto de ejecución de 8 192 tokens,
una ejecución activa y caché de prompts de 256 MiB; la referencia conserva el código
original y 12 000 caracteres de evidencia. Los objetivos de velocidad se cumplen en
esta muestra; la aceptación integral de calidad permanece pendiente.

| Medida | Referencia | Implementación |
| --- | ---: | ---: |
| Respuestas HTTP 200 | 39/60 | 56/60 |
| Respuestas no HTTP 200 | 21 | 4: una aclaración esperada y tres errores |
| Recuperación correcta en capacidades soportadas | 66,0 % | 96,2 % (51/53) |
| Mediana total, respuestas exitosas | 7,58 s | 2,67 s |
| p95 total, respuestas exitosas | 14,25 s | 7,29 s |
| Mediana / p95 de recuperación | 88 / 107 ms | 52 / 97 ms |
| Mediana / p95 de generación | 4,79 / 13,40 s | 2,63 / 5,10 s |

La latencia de éxitos tiene poblaciones distintas: se responden más casos con la
implementación. En los 38 casos con HTTP 200 en ambas versiones, la mediana pasa de
7,37 a 2,66 s y el p95 de 12,11 a 5,16 s. No hay regresiones de recuperación en casos
soportados que superaban la referencia. Esto no certifica ausencia de regresiones
semánticas.

Las 41 respuestas generadas exitosas de capacidades soportadas tienen p95 total de
4,70 s. CVSS por plantilla tiene mediana de 10 ms y p95 de 11 ms; las plantillas de
ausencia de registros, 77 y 110 ms. Se mantienen visibles los fallos C52 y C60 de
preparación y C51 de salida truncada en una consulta de conteo fuera del alcance,
sin sustituirlos por respuestas inventadas o parciales. C46 devuelve la aclaración
422 esperada. C56 no recupera CWE porque ese CVE carece de registros CWE en la
colección; no se modificó el índice para mejorar la métrica.

La medición adicional separa una primera respuesta tras descargar el modelo
(3,81 s, backend ya iniciado y cachés del sistema operativo conservadas), 18 peticiones
con servicios preparados (mediana 2,36 s; p95 5,69 s) y seis peticiones en tres pares
de usuarios (mediana 3,52 s; p95 5,04 s). Las 25 peticiones terminaron correctamente.
Con dos usuarios, la espera del modelo tiene mediana de 1,08 s y p95 de 3,03 s. Estas muestras pequeñas no
demuestran esos percentiles bajo carga sostenida. El arranque del backend comprueba
embeddings y colección por separado: 257 y 50 ms en el último arranque, registrados
en `startup_ready`. Se verificaron los argumentos efectivos de `llama-server`
antes y durante las mediciones finales, sin descargarlo entre ambas series.

Los presupuestos de 6 000 y 12 000 caracteres conservan la misma cobertura de
evidencia: 52/53 casos soportados (98,1 %), con el mismo vacío de CWE en C56.
Se adopta 6 000; este control de recuperación no certifica la calidad semántica de
todas las respuestas.

Se revisaron 15 respuestas representativas, cubriendo cada familia. Descripción,
CVSS, CWE, CAPEC simple, impacto, mitigación, exploits y comparaciones examinadas
están respaldadas por sus registros. Permanecen límites concretos:

- C13 identifica correctamente producto/versión, pero elimina el escape de
  `joomla\!` al citar una cadena CPE; no cumple la copia literal.
- C53, una consulta adversarial, reproduce instrucciones, transforma «before» en
  «or earlier» y presenta prerrequisitos CAPEC como confirmados para el CVE.
- C56 inventa títulos CAPEC y atribuye consecuencias genéricas al CVE en una
  consulta compuesta CWE/CAPEC. La validación mecánica actual no detecta esto.
- C37, fuera del alcance certificado de filtros, infiere el año de publicación
  desde el identificador aunque los metadatos indican otro año.

Por estos hallazgos, no se declara aprobada la aceptación semántica integral.
Las anotaciones por caso distinguen revisión asistida de revisión humana y dejan
sin certificar los casos no examinados.

Pasaron 56 pruebas del backend, nueve del frontend, la compilación del frontend y
la validación de Docker Compose. Los informes confirman 68 973 documentos, misma
configuración/metadatos y una muestra de documentos y embeddings intacta antes y
después. No se ejecutaron operaciones de escritura ni reindexación.

Los datos completos están en [resultados.json](latencia/resultados.json),
[referencia](latencia/baseline-60.json), [60 casos finales](latencia/optimized-60.json),
[arranque y concurrencia](latencia/latency-samples.json) y
[presupuestos de contexto](latencia/context-budgets.json).

## Ejecutor local

Se conserva `ministral3:8B-Q4_K_M`. En este equipo se compararon contextos de
4 096 y 8 192 tokens, una sola ejecución activa y ocho hilos. Las muestras y la
configuración efectiva están en `latencia/runtime-*.json`. El presupuesto de salida
es independiente del contexto total de entrada y salida del ejecutor.

Para reproducir la configuración seleccionada, completar las solicitudes activas,
descargar los modelos cargados y configurar el mismo modelo:

```bash
docker model unload --all
docker model configure --context-size 8192 --keep-alive 1h ministral3:8B-Q4_K_M -- --parallel 1 --threads 8 --no-context-shift --n-gpu-layers all --cache-ram 256
docker model configure show ministral3:8B-Q4_K_M
```

La descarga conserva los archivos del modelo. La configuración se aplica en Docker
Model Runner, no mediante variables del backend. Se verificó con cliente 1.2.6,
servidor 1.2.8 y el `--help` del ejecutor llama.cpp instalado. La
[documentación oficial de Docker](https://docs.docker.com/ai/model-runner/configuration/)
describe el contexto y el paso de argumentos al ejecutor.
En la versión instalada, descargar el modelo eliminó la configuración efectiva:
reaplicar `configure` después de `unload`, generar una solicitud y comprobar los
argumentos del proceso `llama-server`. `configure show` puede mostrar `[]` antes
de cargarlo; eso no demuestra que la próxima ejecución use los parámetros deseados.

Durante el diagnóstico, la GPU estuvo limitada a 10 W, con frecuencias de 210 MHz
para el núcleo y 405 MHz para memoria. El usuario cambió al cargador original y
confirmó modo de rendimiento; las muestras posteriores alcanzaron aproximadamente
40–44 tokens por segundo. Las condiciones de alimentación forman parte de estas
mediciones, no se atribuye toda esa mejora al código.

También se observó que la caché de prompts del ejecutor permitía 8 192 MB por defecto:
tras muchas solicitudes, el proceso llegó a unos 7,8 GB de RAM y aparecieron esperas
prolongadas. `--cache-ram 256` limita ese almacenamiento de estados, conservando la
reutilización de contexto. No corresponde a una caché de respuestas del agente.

## Recuperación y límites

Las preguntas exactas de descripción/CVSS leen NVD por metadatos. CVSS y severidad
se componen con datos NVD del CVE consultado y se validan antes de publicarse. Una
pregunta sobre presencia de registros admite una respuesta directa cuando el tipo
está ausente y existe un registro NVD del CVE; no afirma ausencia fuera de la
recuperación realizada.

La búsqueda semántica mantiene MiniLM ONNX, sus hashes, 384 dimensiones y distancia
coseno. Las lecturas se agrupan por CVE, con hasta tres registros por tipo. Al llenar
un tipo, se retira del filtro y se reinicia el recorrido de los tipos pendientes;
los IDs se deduplican. Así, una descripción NVD única no provoca recorrer todos los
CAPEC asociados para intentar obtener tres descripciones NVD. El límite global del
servicio es de cuatro operaciones activas, incluso cuando una llamada bloqueante
continúa terminando después de su timeout.

La colección y su compatibilidad se reutilizan 60 segundos y se invalidan ante
fallos. Salud renueva la comprobación completa y el conteo. El arranque comprueba
colección/embeddings con tiempos acotados; un fallo se informa sin impedir consultar
salud. El modelo se resuelve con una caché temporal y procesa una generación por vez.
Las desconexiones cancelan trabajo pendiente y cierran la petición al modelo.

Las explicaciones CWE/CAPEC priorizan nombre y descripción de registros genéricos,
sin mezclar descripciones de productos NVD en una hipótesis de explotación. Las
comparaciones simples conservan NVD de ambos CVE. La validación mecánica de citas,
identificadores y números permanece activa; una respuesta truncada no se publica.
En estas comparaciones, el modelo redacta las descripciones y el backend añade
CVSS/severidad desde los metadatos NVD, validando después la respuesta completa.
La validación reconoce por igual versiones con prefijo `v` y sin él, sin aceptar
versiones distintas de las presentes en las fuentes.

## Reproducir las mediciones

Con backend y Chroma disponibles, ejecutar secuencialmente para no mezclar carga:

```bash
PYTHONPATH=backend .venv/bin/python backend/tests/evaluate_agent.py --output /tmp/cve-evaluation.json --timeout 600
PYTHONPATH=backend .venv/bin/python backend/tests/benchmark_context.py --output /tmp/cve-context-budgets.json
PYTHONPATH=backend .venv/bin/python backend/tests/benchmark_latency.py --repeats 3 --output /tmp/cve-latency-samples.json
.venv/bin/python backend/tests/benchmark_runtime.py --output /tmp/cve-runtime-samples.json
```

Se puede seleccionar otro backend con `--api`. `benchmark_latency.py` separa primera
petición, servicios preparados y dos usuarios; una primera petición no demuestra
por sí sola que el modelo estuviera descargado. `benchmark_runtime.py` mide salida
cruda con un límite fijo de 60 tokens, incluyendo `finish_reason`; no publica ese
texto mediante `/api/chat` ni certifica calidad de respuestas.

La suite de 60 casos conserva comprobaciones de conteo, metadatos/configuración y
una muestra de documentos/embeddings antes/después. La comparación de 6 000 y 12 000
caracteres usa exactamente las mismas fuentes y mide cobertura, separadamente de
la generación y la revisión semántica. Los CVE inexistentes requieren fuentes
vacías; ese criterio corregido se aplica tanto al informe anterior como al nuevo.

Los informes excluyen errores del cálculo de latencia exitosa y muestran su número
por separado. `model_wait` y `validation` están incluidos en las etapas y no son
componentes adicionales para sumar al total. Los objetivos son p95 de recuperación
≤1 s, plantillas ≤2 s y respuestas habituales generadas ≤10 s con una solicitud
activa; dos usuarios tienen una medición independiente porque comparten el modelo.

La recuperación por familia no equivale a veracidad semántica. Debe revisarse que
cada cita respalde la afirmación, que los patrones genéricos no se conviertan en
mecanismos confirmados del CVE, y que no se infieran ausencia de impactos o parches.
Filtros exhaustivos, listas completas y conteos siguen fuera de las capacidades
certificadas del chat.
