"""Crea y valida el esquema vacío; nunca sobrescribe una base existente."""

from __future__ import annotations

import argparse
import sqlite3
from contextlib import closing
from pathlib import Path

DIRECTORY = Path(__file__).resolve().parent
TABLES = {
    'NVD_CVE', 'MITRE_CWE', 'MITRE_CAPEC', 'EXPLOIT_DB',
    'CVE_CWE', 'CAPEC_CWE', 'EXPLOIT_CVE',
}
VIEWS = {'VW_CVE_CATALOGO', 'VW_CVE_CPE'}


def validate_empty(connection: sqlite3.Connection) -> None:
    objects = connection.execute(
        "SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"
    ).fetchall()
    if {name for kind, name in objects if kind == 'table'} != TABLES:
        raise RuntimeError('El conjunto de tablas no corresponde al esquema v1')
    if {name for kind, name in objects if kind == 'view'} != VIEWS:
        raise RuntimeError('El conjunto de vistas no corresponde al esquema v1')
    if connection.execute('PRAGMA user_version').fetchone()[0] != 1:
        raise RuntimeError('Versión de esquema inesperada')
    if connection.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
        raise RuntimeError('Falló integrity_check')
    if connection.execute('PRAGMA foreign_key_check').fetchall():
        raise RuntimeError('Hay relaciones inválidas')
    for table in sorted(TABLES):
        if connection.execute(f'SELECT count(*) FROM {table}').fetchone()[0]:
            raise RuntimeError(f'La tabla {table} no está vacía')
    for view in sorted(VIEWS):
        if connection.execute(f'SELECT count(*) FROM {view}').fetchone()[0]:
            raise RuntimeError(f'La vista {view} no está vacía')


def create_database(destination: Path) -> None:
    if sqlite3.sqlite_version_info < (3, 38, 0):
        raise RuntimeError('Se requiere SQLite >= 3.38 con funciones JSON')
    if destination.exists():
        raise FileExistsError(f'La base ya existe; no se sobrescribe: {destination}')
    with closing(sqlite3.connect(':memory:')) as temporary:
        temporary.execute("SELECT json_valid('{}')")
        temporary.executescript((DIRECTORY / 'schema.sql').read_text(encoding='utf-8'))
        validate_empty(temporary)
        # Reserva exclusiva del destino después de validar el SQL en memoria.
        with destination.open('xb'):
            pass
        try:
            with closing(sqlite3.connect(destination)) as result:
                result.execute('PRAGMA foreign_keys = ON')
                temporary.backup(result)
                validate_empty(result)
        except Exception:
            # Solo se retira el archivo que esta ejecución acaba de crear.
            destination.unlink()
            raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destino', type=Path, default=DIRECTORY / 'catalogo.sqlite3')
    args = parser.parse_args()
    try:
        create_database(args.destino)
    except (OSError, sqlite3.Error, RuntimeError) as error:
        parser.exit(1, f'{error}\n')
    print(f'Base vacía validada: {args.destino} (SQLite {sqlite3.sqlite_version})')


if __name__ == '__main__':
    main()
