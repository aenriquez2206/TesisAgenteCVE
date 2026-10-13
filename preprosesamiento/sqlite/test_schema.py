"""Pruebas del contrato relacional; todos los registros se crean en memoria."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from crear_base import DIRECTORY, create_database, validate_empty


class SchemaTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.executescript((DIRECTORY / 'schema.sql').read_text(encoding='utf-8'))

    def tearDown(self):
        self.db.close()

    def add_cve(self, cve_id='CVE-2019-1010218', **fields):
        row = {
            'id': cve_id, 'published': '2019-07-22T18:15:10.917Z',
            'last_modified': '2026-06-17T02:09:52.620Z', 'vuln_status': 'Modified',
        } | fields
        columns = ', '.join(row)
        self.db.execute(
            f'INSERT INTO NVD_CVE ({columns}) VALUES ({", ".join("?" for _ in row)})',
            tuple(row.values()),
        )

    def test_empty_schema_and_reconstruction_without_overwrite(self):
        validate_empty(self.db)
        self.assertEqual(self.db.execute('PRAGMA foreign_keys').fetchone(), (1,))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'catalog.sqlite3'
            create_database(path)
            with sqlite3.connect(path) as db:
                validate_empty(db)
                db.execute('PRAGMA foreign_keys = ON')
                self.assertEqual(db.execute('PRAGMA foreign_keys').fetchone(), (1,))
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                create_database(path)
            self.assertEqual(path.read_bytes(), original)

    def test_orphan_relations_rejected_for_both_parents(self):
        self.add_cve()
        self.db.execute("INSERT INTO MITRE_CWE(id) VALUES ('CWE-200')")
        self.db.execute("INSERT INTO MITRE_CAPEC(id,name) VALUES (1,'Patrón de prueba')")
        self.db.execute("INSERT INTO EXPLOIT_DB(id,description) VALUES (1,'Título de prueba')")
        invalid = [
            ('CVE_CWE', ('CVE-2019-1010218', 'CWE-99999')),
            ('CVE_CWE', ('CVE-2026-99999', 'CWE-200')),
            ('CAPEC_CWE', (99999, 'CWE-200')),
            ('CAPEC_CWE', (1, 'CWE-99999')),
            ('EXPLOIT_CVE', (99999, 'CVE-2019-1010218')),
            ('EXPLOIT_CVE', (1, 'CVE-2026-99999')),
        ]
        for table, values in invalid:
            with self.subTest(table=table, values=values), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(f'INSERT INTO {table} VALUES (?,?)', values)

    def test_catalog_multiple_associations_and_missing_context(self):
        self.add_cve()
        self.add_cve('CVE-2026-1234')
        self.db.execute("INSERT INTO MITRE_CWE(id,name) VALUES ('CWE-120','Debilidad de prueba')")
        self.db.execute("INSERT INTO MITRE_CWE(id) VALUES ('CWE-200')")
        self.db.executemany('INSERT INTO MITRE_CAPEC(id,name) VALUES (?,?)', [(1, 'A'), (2, 'B')])
        self.db.executemany('INSERT INTO EXPLOIT_DB(id,description) VALUES (?,?)', [(1, 'A'), (2, 'B')])
        self.db.executemany('INSERT INTO CVE_CWE VALUES (?,?)', [('CVE-2019-1010218', 'CWE-120'), ('CVE-2019-1010218', 'CWE-200')])
        self.db.executemany('INSERT INTO CAPEC_CWE VALUES (?,?)', [(1, 'CWE-120'), (2, 'CWE-120'), (1, 'CWE-200')])
        self.db.executemany('INSERT INTO EXPLOIT_CVE VALUES (?,?)', [(1, 'CVE-2019-1010218'), (2, 'CVE-2019-1010218'), (1, 'CVE-2026-1234')])
        rows = self.db.execute('SELECT id,cwes_json,exploits_json FROM VW_CVE_CATALOGO ORDER BY id').fetchall()
        self.assertEqual(len(rows), 2)
        weaknesses, exploits = json.loads(rows[0][1]), json.loads(rows[0][2])
        self.assertEqual([w['id'] for w in weaknesses], ['CWE-120', 'CWE-200'])
        self.assertEqual([p['id'] for p in weaknesses[0]['capec']], [1, 2])
        self.assertEqual([p['id'] for p in weaknesses[1]['capec']], [1])
        self.assertFalse(weaknesses[1]['context_available'])
        self.assertIsNone(weaknesses[1]['potential_mitigations'])
        self.assertEqual([e['id'] for e in exploits], [1, 2])
        self.assertEqual(exploits[0]['url'], 'https://www.exploit-db.com/exploits/1')
        self.assertEqual(json.loads(rows[1][1]), [])
        self.assertEqual(len(json.loads(rows[1][2])), 1)
        for table, values in [('CVE_CWE', ('CVE-2019-1010218', 'CWE-120')), ('CAPEC_CWE', (1, 'CWE-120')), ('EXPLOIT_CVE', (1, 'CVE-2019-1010218'))]:
            with self.subTest(table=table), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(f'INSERT INTO {table} VALUES (?,?)', values)

    def test_cve_without_any_associations_stays_visible(self):
        self.add_cve()
        row = self.db.execute('SELECT cwes_json,exploits_json FROM VW_CVE_CATALOGO').fetchone()
        self.assertEqual(tuple(map(json.loads, row)), ([], []))

    def test_json_validation_and_absence(self):
        for field in ['descriptions_json', 'metrics_json', 'weaknesses_json', 'configurations_json', 'references_json']:
            for invalid in ['{broken', 'null', '123', '[]' if field == 'metrics_json' else '{}']:
                with self.subTest(field=field, invalid=invalid), self.assertRaises(sqlite3.IntegrityError):
                    self.add_cve(**{field: invalid})
        self.add_cve(metrics_json='{}', references_json='[]')
        row = self.db.execute('SELECT descriptions_json,metrics_json,references_json FROM NVD_CVE').fetchone()
        self.assertEqual(row, (None, '{}', '[]'))

    def test_all_metrics_and_configuration_logic_preserved(self):
        metrics = {
            'cvssMetricV31': [{'type': 'Secondary', 'cvssData': {'version': '3.1', 'attackVector': 'LOCAL', 'baseScore': 4.7}}],
            'cvssMetricV30': [{'type': 'Secondary', 'cvssData': {'version': '3.0', 'attackVector': 'NETWORK', 'baseScore': 6.5}}],
        }
        configurations = [{'operator': 'AND', 'negate': True, 'nodes': [
            {'operator': 'OR', 'negate': False, 'cpeMatch': [
                {'criteria': 'cpe:2.3:a:test:app:*:*:*:*:*:*:*:*', 'vulnerable': True, 'matchCriteriaId': 'test-id', 'versionEndIncluding': '1.2.103'},
                {'criteria': 'cpe:2.3:o:test:os:*:*:*:*:*:*:*:*', 'vulnerable': False, 'versionStartExcluding': '1.0'},
            ]},
            {'children': [{'cpeMatch': [{'criteria': 'cpe:2.3:h:test:device:*:*:*:*:*:*:*:*', 'vulnerable': True}]}]},
        ]}]
        self.add_cve(metrics_json=json.dumps(metrics), configurations_json=json.dumps(configurations), vuln_status='Awaiting Analysis')
        row = self.db.execute('SELECT metrics_json,configurations_json FROM VW_CVE_CATALOGO').fetchone()
        self.assertEqual(json.loads(row[0]), metrics)
        self.assertEqual(json.loads(row[1]), configurations)
        cpes = self.db.execute('SELECT json_path,vulnerable,version_end_including,version_start_excluding FROM VW_CVE_CPE ORDER BY json_path').fetchall()
        self.assertEqual(len(cpes), 3)
        self.assertEqual(cpes[0][1:], (1, '1.2.103', None))
        self.assertEqual(cpes[1][1:], (0, None, '1.0'))
        self.assertIn('children', cpes[2][0])

    def test_identifier_contract(self):
        for value in ['CVE-2019-123', 'cve-2019-1234', 'CVE-2019-1234x', 'CVE-2019-1234-5']:
            with self.subTest(cve=value), self.assertRaises(sqlite3.IntegrityError):
                self.add_cve(value)
        for value in ['CWE-0', 'CWE-0200', 'CWE-200x', '200', 'cwe-200']:
            with self.subTest(cwe=value), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute('INSERT INTO MITRE_CWE(id) VALUES (?)', (value,))
        self.add_cve()  # Identificador CVE con más de cuatro dígitos finales.

    def test_cascades_and_identifier_update_restriction(self):
        self.add_cve()
        self.db.execute("INSERT INTO MITRE_CWE(id) VALUES ('CWE-200')")
        self.db.execute("INSERT INTO MITRE_CAPEC(id,name) VALUES (1,'Patrón de prueba')")
        self.db.execute("INSERT INTO EXPLOIT_DB(id,description) VALUES (1,'Título de prueba')")
        self.db.execute("INSERT INTO CVE_CWE VALUES ('CVE-2019-1010218','CWE-200')")
        self.db.execute("INSERT INTO CAPEC_CWE VALUES (1,'CWE-200')")
        self.db.execute("INSERT INTO EXPLOIT_CVE VALUES (1,'CVE-2019-1010218')")
        for statement in ["UPDATE NVD_CVE SET id='CVE-2026-1234'", "UPDATE MITRE_CWE SET id='CWE-201'", 'UPDATE MITRE_CAPEC SET id=2', 'UPDATE EXPLOIT_DB SET id=2']:
            with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError):
                self.db.execute(statement)
        self.db.execute('DELETE FROM NVD_CVE')
        for table in ['CVE_CWE', 'EXPLOIT_CVE']:
            self.assertEqual(self.db.execute(f'SELECT count(*) FROM {table}').fetchone(), (0,))
        self.assertEqual(self.db.execute('SELECT count(*) FROM EXPLOIT_DB').fetchone(), (1,))
        self.db.execute('DELETE FROM MITRE_CWE')
        self.assertEqual(self.db.execute('SELECT count(*) FROM CAPEC_CWE').fetchone(), (0,))
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_example_queries_compile_and_run(self):
        self.add_cve()
        self.db.execute("UPDATE NVD_CVE SET metrics_json=?", (json.dumps({'cvssMetricV31': [{'cvssData': {'version': '3.1', 'attackVector': 'LOCAL', 'baseScore': 4.7}}]}),))
        parameters = {'cve_id': 'CVE-2019-1010218', 'desde': '2023-01-01T00:00:00.000Z', 'hasta': '2027-01-01T00:00:00.000Z', 'cpe_criteria': 'cpe:2.3:a:test:app:*:*:*:*:*:*:*:*'}
        statement = ''
        for line in (DIRECTORY / 'consultas.sql').read_text(encoding='utf-8').splitlines(keepends=True):
            statement += line
            if sqlite3.complete_statement(statement):
                with self.subTest(statement=statement[:80]):
                    self.db.execute(statement, parameters).fetchall()
                statement = ''
        self.assertFalse(statement.strip())

    def test_supplied_nvd_fields_fit_and_round_trip_without_filters(self):
        payload = json.loads((DIRECTORY / 'fuentes' / 'NVDExample.json').read_text(encoding='utf-8'))
        for wrapper in payload['vulnerabilities']:
            cve = wrapper['cve']
            fields = {
                'published': cve['published'], 'last_modified': cve['lastModified'],
                'vuln_status': cve['vulnStatus'], 'source_identifier': cve['sourceIdentifier'],
                **{f'{field}_json': json.dumps(cve[field], ensure_ascii=False)
                   for field in ['descriptions', 'metrics', 'weaknesses', 'configurations', 'references']},
            }
            self.add_cve(cve['id'], **fields)
            stored = self.db.execute(
                'SELECT descriptions_json,metrics_json,weaknesses_json,configurations_json,references_json FROM VW_CVE_CATALOGO WHERE id=?',
                (cve['id'],),
            ).fetchone()
            self.assertEqual(list(map(json.loads, stored)), [cve[field] for field in ['descriptions', 'metrics', 'weaknesses', 'configurations', 'references']])
        self.assertEqual(self.db.execute('SELECT count(*) FROM VW_CVE_CATALOGO').fetchone(), (5,))
        self.assertEqual(self.db.execute('SELECT count(*) FROM VW_CVE_CPE').fetchone(), (47,))
        self.assertEqual(self.db.execute('PRAGMA integrity_check').fetchone(), ('ok',))


if __name__ == '__main__':
    unittest.main()
