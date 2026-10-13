# Evaluación reproducible del agente CVE

La suite de 60 casos comprueba las diez familias principales de consulta y veinte
escenarios de robustez. Los casos se construyen de forma determinista a partir de los
CVE que existen en la colección y conservan una referencia compacta al catálogo SQLite
local cuando ese archivo está disponible.

Ejecutar el backend y sus dependencias, luego lanzar desde la raíz:

```bash
PYTHONPATH=backend .venv/bin/python backend/tests/evaluate_agent.py
```

La evaluación solo lee ChromaDB. Escribe un informe JSON en
`docs/validacion_agente_resultados.json` por defecto; se puede indicar otra ruta con `--output` y otro
endpoint con `--api`. El informe guarda cada pregunta, estado HTTP esperado, respuesta,
fuentes con fragmentos acotados, trazas, duración, coincidencia de recuperación y
referencia SQLite y campos para revisión semántica. También compara conteo, metadatos, configuración y una muestra de
documentos/embeddings antes y después.

Cada familia de recuperación recibe cuatro casos. CWE, CAPEC, CPE y exploits incluyen
un caso donde el CVE no tiene ese tipo de registro. Las consultas de filtros, listas y
conteos quedan marcadas como brechas mientras el agente no ofrezca recuperación
estructurada y completa. Los seguimientos ambiguos deben solicitar aclaración.

El informe calcula recuperación automáticamente; la revisión de respuestas queda
marcada como pendiente porque requiere verificar que cada cita respalda la afirmación.
La meta inicial es al menos 90 % de recuperación en capacidades soportadas, junto con
revisión semántica por familia. Esta cifra por sí sola no certifica la validez factual.

Para revisar el flujo actual de detección, ejecutar `npm test` y `npm run build` en
`frontend/`. Esa vista usa hallazgos ilustrativos y respuestas predefinidas, no escanea
la IP ni comprueba si un CVE afecta al objetivo.

## Evaluación de latencia

La suite añade mediana y p95 de las respuestas exitosas, errores y tiempos por
etapa/ruta. Un CVE inexistente se evalúa como recuperación correcta únicamente si
la respuesta esperada llega sin fuentes. Las métricas por familia siguen separadas
de la revisión semántica.

Ver [latencia_agente.md](latencia_agente.md) para reproducir los presupuestos de
contexto, la primera petición, servicios preparados, dos usuarios y la comparación
del ejecutor. La configuración del modelo y los cambios de alimentación se
registran junto a las mediciones para distinguirlos de las mejoras del backend.
