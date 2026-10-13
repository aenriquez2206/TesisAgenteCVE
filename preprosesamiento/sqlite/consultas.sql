-- Solo consultas. Los parámetros :cve_id, :desde, :hasta y :cpe_criteria
-- se enlazan con sqlite3.execute(sql, parametros) en el futuro notebook.

-- 1. Un registro completo; no requiere agrupar filas desde Python.
SELECT * FROM VW_CVE_CATALOGO WHERE id = :cve_id;

-- 2. Recorrer asociaciones, conservando CVE sin contexto o patrones.
SELECT c.id AS cve_id, w.id AS cwe_id, w.name AS cwe_name,
       w.potential_mitigations, p.id AS capec_id, p.name AS capec_name
FROM NVD_CVE c
LEFT JOIN CVE_CWE cw ON cw.cve_id = c.id
LEFT JOIN MITRE_CWE w ON w.id = cw.cwe_id
LEFT JOIN CAPEC_CWE pc ON pc.cwe_id = w.id
LEFT JOIN MITRE_CAPEC p ON p.id = pc.capec_id
WHERE c.id = :cve_id;

-- 3. Exploits; ninguna columna guarda código ejecutable ni rutas de archivos.
SELECT e.id, e.description,
       'https://www.exploit-db.com/exploits/' || e.id AS url
FROM EXPLOIT_CVE ec JOIN EXPLOIT_DB e ON e.id = ec.exploit_id
WHERE ec.cve_id = :cve_id ORDER BY e.id;

-- 4. Publicación, intervalo [desde, hasta). Ejemplo: 2023-01-01T00:00:00.000Z
-- a 2027-01-01T00:00:00.000Z, una vez normalizadas las fechas a UTC.
SELECT * FROM VW_CVE_CATALOGO
WHERE published >= :desde AND published < :hasta;

-- 5. Consultar TODAS las métricas, sin elegir automáticamente una preferida.
SELECT c.id, family.key AS metric_family,
       json_extract(metric.value, '$.source') AS source,
       json_extract(metric.value, '$.type') AS metric_type,
       json_extract(metric.value, '$.cvssData.version') AS version,
       json_extract(metric.value, '$.cvssData.baseScore') AS base_score,
       COALESCE(json_extract(metric.value, '$.cvssData.baseSeverity'),
                json_extract(metric.value, '$.baseSeverity')) AS severity,
       COALESCE(json_extract(metric.value, '$.cvssData.attackVector'),
                json_extract(metric.value, '$.cvssData.accessVector')) AS attack_vector,
       json_extract(metric.value, '$.cvssData.vectorString') AS vector_string
FROM NVD_CVE c
JOIN json_each(c.metrics_json) family
JOIN json_each(family.value) metric
WHERE c.id = :cve_id;

-- 6. Criterios CPE y límites; revisar también configurations_json para decidir
-- aplicabilidad. vulnerable=0 representa condiciones ambientales.
SELECT * FROM VW_CVE_CPE WHERE cve_id = :cve_id ORDER BY json_path;
SELECT * FROM VW_CVE_CPE WHERE criteria = :cpe_criteria;

-- 7. Debilidades pendientes de contexto, sin tratarlas como mitigaciones conocidas.
SELECT id FROM MITRE_CWE WHERE name IS NULL ORDER BY id;

-- 8. La cantidad de filas del catálogo debe coincidir con la cantidad de CVE.
SELECT (SELECT count(*) FROM NVD_CVE) AS cve_count,
       (SELECT count(*) FROM VW_CVE_CATALOGO) AS catalog_count;
PRAGMA integrity_check;
PRAGMA foreign_key_check;
