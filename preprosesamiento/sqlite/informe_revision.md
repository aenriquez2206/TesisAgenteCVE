# Revisión de fuentes y delimitación del catálogo SQLite

Revisión realizada el **5 de octubre de 2026** sobre los archivos locales de
`preprosesamiento/sqlite/fuentes`. La auditoría es reproducible con `revisar_fuentes.py`; su
salida completa está en `revision_fuentes.json`. Los archivos originales no se
modificaron. Este informe documenta la revisión inicial de fuentes: los conteos
siguientes describen los archivos originales, no el contenido actual de SQLite.
La ejecución y los conteos de la base poblada están en `salidas/informe_carga.json`
y `salidas/informe_carga.md`.

## Inventario y formato

| Archivo | Bytes | Registros | Encabezados |
| --- | ---: | ---: | ---: |
| `capec.csv` | 1.433.640 | 559 | 20 |
| `cwe_hardware.csv` | 387.292 | 110 | 23 |
| `cwe_software.csv` | 1.394.999 | 399 | 23 |
| `files_exploits.csv` | 10.182.721 | 47.170 | 17 |
| `NVDExample.json` | 39.957 | 5 | Objeto NVD con array `vulnerabilities`. |

Los CSV se decodifican como UTF-8, sin BOM. En los tres CSV MITRE, cada registro
tiene una columna adicional final cuyo único valor es la cadena vacía; no falta
ninguna columna nombrada. Tras reconocer esa anomalía, no se encontraron
desbordamientos con contenido ni registros incompletos. ExploitDB tiene anchura
consistente. Los IDs de los cuatro CSV son enteros positivos representados en
texto. Los valores con comas se deben leer con un parser CSV que respete comillas.

CAPEC utiliza literalmente el encabezado **`'ID`**, con apóstrofo inicial. Los
valores de esa columna sí son numéricos. El JSON NVD contiene los registros en
`vulnerabilities[].cve`; `resultsPerPage`, `totalResults` y el resto del envoltorio
son metadatos de la respuesta, no columnas de las entidades.

Hashes SHA-256 de las fuentes:

```text
capec.csv          6ba3971aefee4c2ce4d29c2b50b85acab15016133f1f60a765229d780af4f44f
cwe_hardware.csv   54fed63711677c2e7aed1164844da5ca2377cc7fac4d5e09e6ffad8c77d17b27
cwe_software.csv   f4a30c7eaf1c8a4a6045b3be48571f74ee6e23cdbd768e3c40f48f5e67e02101
files_exploits.csv 49ed79cb1bf0878931793318485d21cdc947f1d91ef8accbd09d5d4bf99991b8
NVDExample.json    44802bbaabe6106d96550fe1c5a8ca52869b815f165822ecb235cf88b3febf92
```

## Debilidades CWE

Los archivos contienen 110 CWE de hardware y 399 de software, sin IDs repetidos
dentro de cada archivo. Comparten ocho IDs: **276, 319, 325, 440, 1053, 1220,
1240 y 1241**. La unión tiene **501 IDs únicos**. En los ocho registros comunes
coinciden exactamente `Name`, `Description`, `Extended Description` y
`Potential Mitigations`; se puede conservar una sola entidad por ID.

| Campo seleccionado | Vacíos hardware | Vacíos software | Vacíos en unión única |
| --- | ---: | ---: | ---: |
| `Name` | 0 | 0 | 0 |
| `Description` | 0 | 0 | 0 |
| `Extended Description` | 7 | 187 | 189 |
| `Potential Mitigations` | 4 | 159 | 160 |

Los campos de mitigaciones contienen estructuras textuales como
`::PHASE:...:STRATEGY:...:DESCRIPTION:...::`. El esquema mantiene el texto original
para no perder fases, estrategias ni explicaciones. La futura conversión a texto
para RAG deberá respetar esas relaciones, sin rellenar mitigaciones inexistentes.

Los dos CSV no equivalen al catálogo CWE completo: incluyen selecciones que
omiten debilidades referenciadas por las otras fuentes.

## Patrones CAPEC y cobertura CWE

CAPEC contiene 559 IDs únicos. `Related Weaknesses` utiliza listas de IDs como
`::276::285::434::`. Se encontraron **1.214 menciones**, equivalentes a **1.212
pares CAPEC–CWE únicos**. Dos pares aparecen dos veces:

- CAPEC-545 → CWE-1258.
- CAPEC-644 → CWE-308.

Los patrones referencian **336 CWE distintos**. De ellos, 122 no aparecen en los
CSV CWE; **627 pares únicos** apuntan a esas debilidades ausentes. Los IDs
completos están en `capec.missing_cwe_ids` del informe JSON.

| Campo seleccionado | Registros vacíos |
| --- | ---: |
| `Name` | 0 |
| `Description` | 2 |
| `Execution Flow` | 320 |
| `Prerequisites` | 69 |
| `Consequences` | 190 |
| `Related Weaknesses` | 109 |

`Execution Flow`, `Prerequisites` y `Consequences` conservan sus delimitadores y
contenido original. Un patrón sin CWE relacionado puede existir en `MITRE_CAPEC`,
aunque no aparezca asociado a un CVE en el catálogo.

La decisión adoptada es permitir filas CWE con solo el ID. Si posteriormente se
cargan únicamente estas fuentes originales, se esperan **623 filas CWE**: 501
con contexto de los CSV y 122 con contexto `NULL`. La muestra anual descargada
desde NVD puede aportar IDs ausentes adicionales. No se consultará MITRE ni se inventarán nombres,
descripciones o mitigaciones para completarlas.

## ExploitDB y códigos CVE

`files_exploits.csv` contiene **47.170 filas**, correspondientes a **46.698 IDs
únicos**. Hay **461 IDs repetidos** y **472 filas adicionales**. Para los IDs
repetidos no se encontraron diferencias en `description` ni en `codes`; cada
exploit puede cargarse una sola vez. Los IDs repetidos y sus frecuencias están
en `exploit_db.duplicate_ids` del informe JSON.

El archivo no tiene una columna `cve`. Las asociaciones están en **`codes`**,
mezcladas con OSVDB y otros códigos y separadas por `;`. Hay 14.640 filas con
`codes` vacío y 1.990 filas con más de un CVE válido. Por ello, una FK escalar
en `EXPLOIT_DB` no representa las relaciones reales.

Se distinguen dos conteos para no convertir errores de formato en asociaciones:

| Criterio de revisión | Pares exploit–CVE únicos | CVE distintos |
| --- | ---: | ---: |
| Búsqueda de subcadenas con patrón CVE | 30.390 | 25.091 |
| Token completo válido, quitando solo espacios exteriores | 30.389 | 25.090 |

Con el segundo criterio, 19.741 filas no contienen CVE válido. Hay **25 tokens
con anomalías de formato original**; seis quedan válidos al retirar espacios
exteriores. Entre los restantes se encuentran `CVE-n/a`, `CVE-na`, guiones Unicode,
`CVE-2015- 5698`, `CVE-cve : 2023-30367` y `CVE-2017-18344.`. La búsqueda de
subcadenas reconoce este último a pesar del punto; la validación completa lo
excluye. Todos los tokens están documentados con su ID de exploit y con la
indicación `valid_after_trim`.

Estos conteos no son una transformación de carga. En el futuro notebook, los
tokens mal formados se reportarán y no se corregirán mediante inferencia. Se
cargará el título del exploit y se vincularán los CVE efectivamente presentes en
NVD. Los demás enlaces se reportarán fuera del catálogo; podrán reevaluarse
desde el CSV cuando se amplíe el corpus NVD.

## Muestra NVD y relaciones disponibles

Los cinco CVE tienen estado `Modified`, descripciones en inglés y español,
métricas, debilidades, configuraciones y referencias.

| CVE | Publicación | Debilidades | CPE | Referencias | Exploits asociados |
| --- | --- | --- | ---: | ---: | ---: |
| CVE-2019-1010 | 2019-06-12 | CWE-200 | 19 | 2 | 0 |
| CVE-2019-1011 | 2019-06-12 | CWE-200 | 4 | 2 | 0 |
| CVE-2019-1012 | 2019-06-12 | CWE-200 | 19 | 2 | 0 |
| CVE-2019-1013 | 2019-06-12 | CWE-200 | 4 | 4 | 0 |
| CVE-2019-1010218 | 2019-07-22 | CWE-120 y CWE-787 | 1 | 2 | 0 |

Todos fueron modificados el 17 de junio de 2026. **Ninguno fue publicado entre
2023 y 2026**: filtrar por `published` excluiría toda la muestra; filtrar por
`lastModified` es un criterio distinto. El esquema conserva ambos campos y no
impone el rango temporal.

Los cuatro CVE de Windows tienen CVSS 3.1 `LOCAL`, puntuación 4,7, y CVSS 3.0
`NETWORK`, puntuación 6,5; ambas métricas son `Secondary`. También tienen CVSS
2.0 `Primary`, vector de acceso `NETWORK` y puntuación 4,3. El quinto tiene CVSS
3.1 `Primary`, `NETWORK`, 7,5, además de CVSS 2.0. Por tanto, una selección por
`NETWORK` requiere una política de versión y fuente explícita; el esquema
preserva todas las métricas sin decidirla.

CWE-200 falta en ambos CSV CWE, mientras que CWE-120 y CWE-787 están presentes.
El quinto CVE aporta dos atribuciones de debilidad con fuentes y tipos distintos,
que se mantienen en `weaknesses_json`. Las referencias del quinto CVE comparten
una URL pero tienen fuentes distintas, por lo que no deben deduplicarse solo por
URL. En total, la muestra contiene 47 entradas CPE, incluidos límites de versión.

El cruce por identificador contra ExploitDB da **cero asociaciones**. Esto solo
describe la cobertura de los archivos entregados, no demuestra inexistencia de
exploits. No se crearán vínculos por similitud textual ni por deducciones desde
URLs. Los CAPEC asociados se obtendrán exclusivamente a través de CWE.

## Delimitación y resultado del diseño

El esquema contiene cuatro entidades y tres tablas puente muchos a muchos.
Preserva únicamente los campos solicitados, sus relaciones y las proyecciones
derivadas para consulta. El mapeo exacto está en `diccionario_datos.md`.

- NVD conserva estructuras JSON completas de los campos seleccionados, con
  fuentes, idiomas y operadores lógicos. No almacena todo el objeto `cve`.
- CWE y CAPEC conservan como texto sus campos compuestos delimitados.
- ExploitDB conserva ID y título; la URL se calcula a partir del ID.
- Las PK compuestas impiden asociaciones repetidas. Las FK exigen entidades
  existentes; se admiten CWE de contexto desconocido, pero no CVE ficticios.
- `VW_CVE_CATALOGO` devuelve una fila por CVE con CWE y sus CAPEC anidados y una
  lista independiente de exploits; los CVE sin asociaciones permanecen visibles.
- `VW_CVE_CPE` expone criterios, condiciones ambientales, rangos y rutas JSON;
  para determinar aplicabilidad se conserva el árbol original de configuraciones.

La base no impone filtros de admisión del corpus. El estado `Modified` por sí
solo no obliga a que una métrica sea `Primary` ni a que los catálogos CWE aporten
el contexto requerido, como muestra esta revisión. El notebook de carga
valida cobertura, filtros de métricas y consistencia entre JSON y tablas puente
durante su carga transaccional desde Jupyter. Sus resultados actuales están en
`salidas/informe_carga.json`.
