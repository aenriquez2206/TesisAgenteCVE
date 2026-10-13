"""Ejecuta y guarda el notebook con el Python actual, sin registrar kernels globales."""
import sys
from pathlib import Path

import nbformat
from jupyter_client import KernelManager
from nbclient import NotebookClient


def main():
    path = Path(__file__).resolve().parent.parent / 'indexar_chroma.ipynb'
    notebook = nbformat.read(path, as_version=4)
    for cell in notebook.cells:
        if cell.cell_type == 'code':
            cell.outputs = []
            cell.execution_count = None
    manager = KernelManager(kernel_name='python3')
    manager.kernel_spec.argv[0] = sys.executable

    def started(cell, cell_index, **kwargs):
        if cell.cell_type == 'code':
            print(f'Ejecutando celda {cell_index + 1}/{len(notebook.cells)}', flush=True)

    client = NotebookClient(notebook, km=manager, timeout=None,
                            resources={'metadata': {'path': str(path.parent)}}, on_cell_start=started)
    try:
        client.execute()
    finally:
        # Guarda el progreso también ante errores, para que el diagnóstico sea visible.
        nbformat.write(notebook, path)
    errors = [output for cell in notebook.cells if cell.cell_type == 'code'
              for output in cell.outputs if output.output_type == 'error']
    if errors:
        raise RuntimeError('El notebook terminó con errores')
    print(f'Notebook ejecutado y guardado: {path}', flush=True)


if __name__ == '__main__':
    main()
