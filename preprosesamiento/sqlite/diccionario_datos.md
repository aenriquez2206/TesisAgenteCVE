# Diccionario de datos — esquema v1

Todas las tablas son `STRICT`: SQLite verifica los tipos almacenados. Las claves
externas se activan por conexión. Los identificadores de CVE y CWE usan su forma
canónica; los IDs CAPEC y ExploitDB son enteros positivos. La carga siempre debe
proporcionar los IDs de origen, sin generar identificadores propios.

## NVD_CVE

Cada registro procede de `vulnerabilities[].cve` de la API NVD 2.0.
`fuentes/NVDExample.json` conserva el mismo formato como fixture de prueba;
sus cinco registros no se incorporan a la muestra anual.

| Columna | Tipo | Nulable | Origen y significado |
| --- | --- | --- | --- |
| `id` | TEXT, PK | No | `id`, patrón `CVE-AAAA-NNNN…`, con al menos cuatro dígitos finales. |
| `published` | TEXT | No | `published`; fecha de publicación. |
| `last_modified` | TEXT | No | `lastModified`; fecha de modificación. |
| `vuln_status` | TEXT | No | `vulnStatus`; conserva el estado recibido. |
| `source_identifier` | TEXT | Sí | `sourceIdentifier`. |
| `descriptions_json` | TEXT JSON array | Sí | `descriptions`; todos los idiomas y textos. |
| `metrics_json` | TEXT JSON object | Sí | `metrics`; todas las versiones, fuentes y métricas. |
| `weaknesses_json` | TEXT JSON array | Sí | `weaknesses`; grupos, fuentes, tipos y descripciones originales. |
| `configurations_json` | TEXT JSON array | Sí | `configurations`; árbol lógico completo, criterios CPE y rangos. |
| `references_json` | TEXT JSON array | Sí | `references`; URL, fuente y etiquetas, incluidas entradas con URL repetida. |

Los `CHECK` verifican JSON válido y el tipo de su raíz, no el esquema completo de
cada elemento. `NULL` expresa campo ausente; `[]` o `{}` expresan una colección
presente y vacía. No se reduce una colección a su primer elemento. En la muestra,
el campo correcto para debilidades es `weaknesses`, en plural.

Las fechas y el estado deben ser textos no vacíos. El DDL no valida su significado
ni filtra su valor. La carga del notebook valida las fechas y las normaliza a
UTC con precisión uniforme para que el orden textual represente el cronológico.

## MITRE_CWE

Unifica `cwe_hardware.csv` y `cwe_software.csv`; no incorpora columnas de dominio,
jerarquía, severidad, ejemplos o patrones adicionales.

| Columna | Tipo | Nulable | Columna de origen |
| --- | --- | --- | --- |
| `id` | TEXT, PK | No | `CWE-ID`, anteponiendo `CWE-`; sin ceros iniciales. |
| `name` | TEXT | Sí | `Name`; si está presente debe ser no vacío. |
| `description` | TEXT | Sí | `Description`. |
| `extended_description` | TEXT | Sí | `Extended Description`. |
| `potential_mitigations` | TEXT | Sí | `Potential Mitigations`; texto compuesto original. |

Un ID ausente de los dos CSV se puede representar mediante una fila con solo
`id`; sus otros campos quedan `NULL`. Esto registra una referencia conocida,
sin afirmar que exista contexto MITRE completo en las fuentes suministradas.

## MITRE_CAPEC

| Columna | Tipo | Nulable | Columna de origen |
| --- | --- | --- | --- |
| `id` | INTEGER, PK | No | `'ID` en el archivo suministrado. |
| `name` | TEXT | No | `Name`; texto no vacío. |
| `description` | TEXT | Sí | `Description`. |
| `execution_flow` | TEXT | Sí | `Execution Flow`. |
| `prerequisites` | TEXT | Sí | `Prerequisites`. |
| `consequences` | TEXT | Sí | `Consequences`. |

`Related Weaknesses` se materializa exclusivamente en `CAPEC_CWE` como pares
únicos. El esquema no conserva las otras columnas del CSV, incluida `Mitigations`,
porque no forman parte de la delimitación solicitada para CAPEC.

## EXPLOIT_DB

| Columna | Tipo | Nulable | Columna de origen |
| --- | --- | --- | --- |
| `id` | INTEGER, PK | No | `id`. |
| `description` | TEXT | No | `description`; título no vacío. |

Los CVE se extraen de `codes` para poblar `EXPLOIT_CVE`; no se almacena la columna
`codes` completa, el archivo, código fuente, fechas, autor ni plataformas del
exploit. La URL se deriva del ID al consultar. Un exploit puede existir sin
asociaciones y puede relacionarse con varios CVE presentes en NVD.

## Tablas puente y reglas relacionales

| Tabla | PK compuesta | FK hacia |
| --- | --- | --- |
| `CVE_CWE` | `(cve_id TEXT, cwe_id TEXT)` | `NVD_CVE(id)`, `MITRE_CWE(id)`. |
| `CAPEC_CWE` | `(capec_id INTEGER, cwe_id TEXT)` | `MITRE_CAPEC(id)`, `MITRE_CWE(id)`. |
| `EXPLOIT_CVE` | `(exploit_id INTEGER, cve_id TEXT)` | `EXPLOIT_DB(id)`, `NVD_CVE(id)`. |

Todas las columnas de las tablas puente son `NOT NULL`. No existe relación
directa CVE–CAPEC: se obtiene a través de CWE. Las PK evitan pares repetidos y
las FK evitan relaciones sin entidades. Todas utilizan `ON DELETE CASCADE` para
retirar asociaciones y `ON UPDATE RESTRICT` para mantener IDs estables. Eliminar
una entidad no elimina las entidades del otro extremo.

Las PK ya indexan el primer componente del par; los índices auxiliares cubren
el orden inverso. NVD cuenta además con índices de publicación, modificación y
estado. Las vistas no materializan datos ni tienen índices propios.

## Contrato de VW_CVE_CATALOGO

Devuelve todas las columnas de `NVD_CVE` y dos columnas adicionales de texto JSON:

| Columna | Contenido |
| --- | --- |
| `cwes_json` | Lista de CWE ordenados por ID numérico; cada objeto contiene los cinco campos de CWE, `context_available` y su lista `capec`. |
| `exploits_json` | Lista ordenada por ID; cada objeto contiene `id`, `description` y `url`. |

Cada elemento de `capec` contiene los seis campos de `MITRE_CAPEC`, ordenado por
ID. `context_available` es un booleano derivado de `name IS NOT NULL`: informa
si se cargó contexto, sin garantizar que todos los campos estén completos. Las
colecciones sin asociaciones devuelven `[]`, nunca `[null]` ni objetos vacíos.

Un patrón compartido por dos CWE aparece bajo ambos: conserva las dos relaciones.
Los exploits se agregan independientemente, por lo que no se multiplican al
combinarse con CWE o CAPEC. Toda fila NVD aparece exactamente una vez. No hay
traducción, selección de idioma, clasificación de severidad preferida ni texto
para embeddings en esta vista.

## Contrato de VW_CVE_CPE

Cada fila representa un objeto de un array `cpeMatch` localizado dentro de
`configurations_json`:

| Columna | Tipo derivado y origen |
| --- | --- |
| `cve_id` | TEXT; ID NVD. |
| `json_path` | TEXT; ruta completa del objeto en el JSON original. |
| `criteria` | TEXT; cadena CPE original. |
| `vulnerable` | INTEGER 1/0 o NULL; valor del campo JSON. |
| `match_criteria_id` | TEXT o NULL; `matchCriteriaId`. |
| `version_start_including` | TEXT o NULL; `versionStartIncluding`. |
| `version_start_excluding` | TEXT o NULL; `versionStartExcluding`. |
| `version_end_including` | TEXT o NULL; `versionEndIncluding`. |
| `version_end_excluding` | TEXT o NULL; `versionEndExcluding`. |

La vista incluye `vulnerable=false` y niveles adicionales de anidamiento. No
deduplica criterios: dos condiciones iguales en ramas diferentes conservan sus
rutas. Las versiones son texto; no se ordenan como números ni se evalúan rangos.
No se divide la cadena CPE por `:`, pues esa operación requiere respetar escapes.
Una coincidencia CPE aislada no prueba aplicabilidad; los operadores y negaciones
se consultan en `configurations_json`.
