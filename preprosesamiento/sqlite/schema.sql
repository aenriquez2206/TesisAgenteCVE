-- Esquema v1. SQLite >= 3.38 con funciones JSON.
-- Aplicar sobre una base nueva. No contiene INSERT ni filtros del corpus.
PRAGMA foreign_keys = ON;
BEGIN;

CREATE TABLE NVD_CVE (
    id TEXT PRIMARY KEY NOT NULL
        CHECK (id GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9]*'
               AND length(id) >= 13 AND substr(id, 10) NOT GLOB '*[^0-9]*'),
    published TEXT NOT NULL CHECK (length(trim(published)) > 0),
    last_modified TEXT NOT NULL CHECK (length(trim(last_modified)) > 0),
    vuln_status TEXT NOT NULL CHECK (length(trim(vuln_status)) > 0),
    source_identifier TEXT,
    descriptions_json TEXT CHECK (
        CASE WHEN descriptions_json IS NULL THEN 1
             WHEN json_valid(descriptions_json) THEN json_type(descriptions_json) = 'array'
             ELSE 0 END),
    metrics_json TEXT CHECK (
        CASE WHEN metrics_json IS NULL THEN 1
             WHEN json_valid(metrics_json) THEN json_type(metrics_json) = 'object'
             ELSE 0 END),
    weaknesses_json TEXT CHECK (
        CASE WHEN weaknesses_json IS NULL THEN 1
             WHEN json_valid(weaknesses_json) THEN json_type(weaknesses_json) = 'array'
             ELSE 0 END),
    configurations_json TEXT CHECK (
        CASE WHEN configurations_json IS NULL THEN 1
             WHEN json_valid(configurations_json) THEN json_type(configurations_json) = 'array'
             ELSE 0 END),
    references_json TEXT CHECK (
        CASE WHEN references_json IS NULL THEN 1
             WHEN json_valid(references_json) THEN json_type(references_json) = 'array'
             ELSE 0 END)
) STRICT;

CREATE TABLE MITRE_CWE (
    id TEXT PRIMARY KEY NOT NULL
        CHECK (id GLOB 'CWE-[1-9]*' AND substr(id, 5) NOT GLOB '*[^0-9]*'),
    -- NULL permite conservar IDs referenciados sin inventar contexto MITRE.
    name TEXT CHECK (name IS NULL OR length(trim(name)) > 0),
    description TEXT,
    extended_description TEXT,
    potential_mitigations TEXT
) STRICT;

CREATE TABLE MITRE_CAPEC (
    id INTEGER PRIMARY KEY CHECK (id > 0),
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    description TEXT,
    execution_flow TEXT,
    prerequisites TEXT,
    consequences TEXT
) STRICT;

CREATE TABLE EXPLOIT_DB (
    id INTEGER PRIMARY KEY CHECK (id > 0),
    description TEXT NOT NULL CHECK (length(trim(description)) > 0)
) STRICT;

CREATE TABLE CVE_CWE (
    cve_id TEXT NOT NULL REFERENCES NVD_CVE(id) ON DELETE CASCADE ON UPDATE RESTRICT,
    cwe_id TEXT NOT NULL REFERENCES MITRE_CWE(id) ON DELETE CASCADE ON UPDATE RESTRICT,
    PRIMARY KEY (cve_id, cwe_id)
) STRICT;

CREATE TABLE CAPEC_CWE (
    capec_id INTEGER NOT NULL REFERENCES MITRE_CAPEC(id) ON DELETE CASCADE ON UPDATE RESTRICT,
    cwe_id TEXT NOT NULL REFERENCES MITRE_CWE(id) ON DELETE CASCADE ON UPDATE RESTRICT,
    PRIMARY KEY (capec_id, cwe_id)
) STRICT;

CREATE TABLE EXPLOIT_CVE (
    exploit_id INTEGER NOT NULL REFERENCES EXPLOIT_DB(id) ON DELETE CASCADE ON UPDATE RESTRICT,
    cve_id TEXT NOT NULL REFERENCES NVD_CVE(id) ON DELETE CASCADE ON UPDATE RESTRICT,
    PRIMARY KEY (exploit_id, cve_id)
) STRICT;

CREATE INDEX idx_nvd_published ON NVD_CVE(published);
CREATE INDEX idx_nvd_last_modified ON NVD_CVE(last_modified);
CREATE INDEX idx_nvd_vuln_status ON NVD_CVE(vuln_status);
CREATE INDEX idx_cve_cwe_reverse ON CVE_CWE(cwe_id, cve_id);
CREATE INDEX idx_capec_cwe_reverse ON CAPEC_CWE(cwe_id, capec_id);
CREATE INDEX idx_exploit_cve_reverse ON EXPLOIT_CVE(cve_id, exploit_id);

-- Cada colección se agrega de forma independiente: no hay producto cartesiano.
-- json(item) evita que los objetos se conviertan en cadenas JSON escapadas.
CREATE VIEW VW_CVE_CATALOGO AS
SELECT c.*,
    (
        SELECT json_group_array(json(item)) FROM (
            SELECT json_object(
                'id', w.id,
                'name', w.name,
                'description', w.description,
                'extended_description', w.extended_description,
                'potential_mitigations', w.potential_mitigations,
                'context_available', json(CASE WHEN w.name IS NULL THEN 'false' ELSE 'true' END),
                'capec', json((
                    SELECT json_group_array(json(item)) FROM (
                        SELECT json_object(
                            'id', p.id,
                            'name', p.name,
                            'description', p.description,
                            'execution_flow', p.execution_flow,
                            'prerequisites', p.prerequisites,
                            'consequences', p.consequences
                        ) AS item
                        FROM CAPEC_CWE pc
                        JOIN MITRE_CAPEC p ON p.id = pc.capec_id
                        WHERE pc.cwe_id = w.id
                        ORDER BY p.id
                    )
                ))
            ) AS item
            FROM CVE_CWE cw
            JOIN MITRE_CWE w ON w.id = cw.cwe_id
            WHERE cw.cve_id = c.id
            ORDER BY CAST(substr(w.id, 5) AS INTEGER)
        )
    ) AS cwes_json,
    (
        SELECT json_group_array(json(item)) FROM (
            SELECT json_object(
                'id', e.id,
                'description', e.description,
                'url', 'https://www.exploit-db.com/exploits/' || e.id
            ) AS item
            FROM EXPLOIT_CVE ec
            JOIN EXPLOIT_DB e ON e.id = ec.exploit_id
            WHERE ec.cve_id = c.id
            ORDER BY e.id
        )
    ) AS exploits_json
FROM NVD_CVE c;

-- Proyección para búsqueda, NO evaluación de aplicabilidad.
-- Se conserva la ruta y el JSON íntegro en NVD_CVE para interpretar AND/OR/negate.
-- json_tree encuentra cpeMatch también en estructuras con niveles adicionales.
CREATE VIEW VW_CVE_CPE AS
SELECT c.id AS cve_id,
    match.fullkey AS json_path,
    json_extract(match.value, '$.criteria') AS criteria,
    json_extract(match.value, '$.vulnerable') AS vulnerable,
    json_extract(match.value, '$.matchCriteriaId') AS match_criteria_id,
    json_extract(match.value, '$.versionStartIncluding') AS version_start_including,
    json_extract(match.value, '$.versionStartExcluding') AS version_start_excluding,
    json_extract(match.value, '$.versionEndIncluding') AS version_end_including,
    json_extract(match.value, '$.versionEndExcluding') AS version_end_excluding
FROM NVD_CVE c
JOIN json_tree(c.configurations_json) AS match
JOIN json_tree(c.configurations_json) AS parent ON parent.id = match.parent
WHERE parent.key = 'cpeMatch' AND parent.type = 'array' AND match.type = 'object';

PRAGMA user_version = 1;
COMMIT;
