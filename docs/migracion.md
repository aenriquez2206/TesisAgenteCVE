# Migración a `preprosesamiento`

Antes de mover archivos se generó [`migration-manifest.json`](../migration-manifest.json), con origen, destino, tamaño y SHA-256 de los 184 archivos en el procesamiento y scripts auxiliares. Las carpetas `procesoExtraccion/`, `extracionPrubea.py` y `pruebasTemporales/` pasaron a `preprosesamiento/`.

Se conservaron dentro del árbol trasladado las fuentes CSV y JSON, el catálogo SQLite, las cachés, los respaldos y los informes. Se ajustaron notebooks, lector de diagnóstico, pruebas y documentación para las rutas nuevas. Los informes anteriores contienen rutas absolutas históricas; sirven como evidencia de su ejecución y no son configuración activa del chat.

`chroma_data/`, `.env`, `.venv` y el repositorio anidado `chromadb-ui/` permanecieron en la raíz. Compose mantiene el mismo volumen para ChromaDB. No se volvió a indexar la colección al crear el chat.

La comparación de hashes del manifiesto debe aplicarse a datos y artefactos trasladados. Los archivos de código y notebooks cambiaron de forma intencional para actualizar rutas y comandos.

## Auditoría de la implementación del chat

El inventario previo a esta ampliación está en `inventario.json`: 262 archivos,
excluyendo `.git`, `.venv`, `node_modules`, `__pycache__` y `dist`. No se efectuó
una segunda migración. Se verificaron los 184 destinos del manifiesto histórico.

Se encontraron ocho diferencias anteriores a esta ampliación: documentación de
preprocesamiento/SQLite, dos notebooks, el test de indexación, el script de extracción,
un archivo bytecode y `sqlite/informe_revision.md`. En este último se comprobó que
la única diferencia respecto a Git es la ruta `procesoExtraccion/sqlite/fuentes` →
`preprosesamiento/sqlite/fuentes`. No se corrigieron informes históricos de ejecución.
Los demás datos y artefactos del manifiesto coinciden con sus hashes originales.

El árbol de trabajo ya contenía cambios de migración, archivos de aplicación sin
seguimiento y una modificación de `chroma_data/chroma.sqlite3` al comenzar. Esta
implementación conserva ese trabajo previo y no modifica las bases originales.
