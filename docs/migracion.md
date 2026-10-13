# Migración a `preprosesamiento`

Antes de mover archivos se generó [`migration-manifest.json`](../migration-manifest.json), con origen, destino, tamaño y SHA-256 de los 184 archivos en el procesamiento y scripts auxiliares. Las carpetas `procesoExtraccion/`, `extracionPrubea.py` y `pruebasTemporales/` pasaron a `preprosesamiento/`.

Se conservaron dentro del árbol trasladado las fuentes CSV y JSON, el catálogo SQLite, las cachés, los respaldos y los informes. Se ajustaron notebooks, lector de diagnóstico, pruebas y documentación para las rutas nuevas. Los informes anteriores contienen rutas absolutas históricas; sirven como evidencia de su ejecución y no son configuración activa del chat.

`chroma_data/`, `.env`, `.venv` y el repositorio anidado `chromadb-ui/` permanecieron en la raíz. Compose mantiene el mismo volumen para ChromaDB. No se volvió a indexar la colección al crear el chat.

La comparación de hashes del manifiesto debe aplicarse a datos y artefactos trasladados. Los archivos de código y notebooks cambiaron de forma intencional para actualizar rutas y comandos.
