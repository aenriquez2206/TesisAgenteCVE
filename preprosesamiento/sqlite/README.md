# Esquema y catálogo SQLite v1

El esquema vigente contiene siete tablas, seis índices auxiliares y dos vistas.
La base `catalogo.sqlite3` se carga con el notebook `../cargar_catalogo.ipynb`.
Las instrucciones de instalación, ejecución y selección anual están en
[el README del proceso](../README.md).

| Archivo o carpeta | Propósito |
| --- | --- |
| `schema.sql` | DDL v1; no contiene INSERT ni filtros del corpus. |
| `catalogo.sqlite3` | Base poblada por la ejecución real del notebook. |
| `carga_catalogo.py` | Cliente NVD, caché, muestreo, transformaciones e INSERTS atómicos. |
| `ejecutar_notebook.py` | Ejecuta y guarda el notebook usando el Python actual. |
| `diccionario_datos.md` | Tipos, claves, mapeos y contrato de las vistas. |
| `consultas.sql` | Consultas parametrizadas independientes. |
| `informe_revision.md` / `revision_fuentes.json` | Auditoría de los cinco archivos originales, no conteos de la carga actual. |
| `revisar_fuentes.py` | Repite la auditoría sin modificar las fuentes ni SQLite. |
| `crear_base.py` | Crea otra base vacía; rechaza sobrescribir una existente. |
| `test_schema.py` / `test_carga.py` | Verificación aislada del esquema y del flujo de carga. |
| `fuentes/` | Cuatro CSV y muestra NVD de cinco registros, conservados por hash. |
| `salidas/` | Selección, validación, caché comprimida y respaldos por ejecución. |

## Consultar sin modificar la base

```python
import json
import sqlite3
from contextlib import closing

with closing(sqlite3.connect("preprosesamiento/sqlite/catalogo.sqlite3")) as conexion:
    conexion.execute("PRAGMA foreign_keys = ON")
    conexion.row_factory = sqlite3.Row
    fila = conexion.execute(
        "SELECT * FROM VW_CVE_CATALOGO ORDER BY id LIMIT 1"
    ).fetchone()
    if fila:
        registro = dict(fila)
        registro["cwes_json"] = json.loads(registro["cwes_json"])
        registro["exploits_json"] = json.loads(registro["exploits_json"])
```

Activar FK en cada conexión antes de iniciar una transacción: la configuración
no queda almacenada en el archivo. `consultas.sql` contiene consultas separadas;
en Jupyter, utilizar `execute(sql, parametros)` para cada sentencia. No enlazar
parámetros mediante `executescript`.

## Reconstruir un esquema vacío separado

```bash
.venv/bin/python preprosesamiento/sqlite/crear_base.py --destino /tmp/catalogo_cve_nuevo.sqlite3
```

El destino debe ser nuevo. El creador valida el DDL en memoria y comprueba
`user_version=1`, las tablas y vistas esperadas, integridad y ausencia de filas.
No migra ni sobrescribe la base poblada.

## Contrato de la carga

La población NVD se obtiene de la API; la muestra histórica `fuentes/NVDExample.json`
solo sirve para pruebas. El filtro NETWORK acepta cualquier métrica 3.0/3.1
válida y no elimina las otras métricas del JSON. El DDL no restringe fechas,
estados, vectores ni referencias: esos criterios se aplican en el notebook.

Se preparan todas las filas antes de abrir la transacción y se respaldan los
datos anteriores. La carga sustituye entidades y asociaciones mediante DELETE
en orden de dependencias e INSERTS parametrizados, con rollback ante fallos.
La selección debe completar las cuatro cuotas antes de tocar la base.

La consistencia entre `weaknesses_json` y `CVE_CWE` se construye en la transformación;
las FK garantizan existencia de entidades y las PK compuestas evitan pares
repetidos. Los campos ausentes mantienen NULL; las listas presentes vacías
mantienen `[]`. Las debilidades desconocidas conservan su ID sin inventar contexto.
Los rangos y operadores CPE permanecen íntegros en `configurations_json`.

## Referencias técnicas

- [SQLite: claves foráneas](https://www.sqlite.org/foreignkeys.html).
- [SQLite: funciones JSON](https://www.sqlite.org/json1.html).
- [NVD: API de vulnerabilidades](https://nvd.nist.gov/developers/vulnerabilities).

Esta base es independiente del `chroma.sqlite3` administrado por Chroma.
