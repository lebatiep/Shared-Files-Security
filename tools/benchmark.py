"""Run with: python -m tools.benchmark --repeats 3."""

import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
from tempfile import TemporaryDirectory
from time import perf_counter

from secure_share.models import OperationStatus, ReceiveRequest, SendRequest
from .demo import prepare_demo
from .compare_files import compare_files


def _revision():
    try:
        return subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return os.environ.get('GITHUB_SHA')


def _memory_bytes():
    if os.name != 'nt':
        try:
            return os.sysconf('SC_PHYS_PAGES') * os.sysconf('SC_PAGE_SIZE')
        except (AttributeError, OSError, ValueError):
            return None

    import ctypes

    class MemoryStatus(ctypes.Structure):
        _fields_ = [
            ('length', ctypes.c_uint32),
            ('memory_load', ctypes.c_uint32),
            ('total_physical', ctypes.c_uint64),
            ('available_physical', ctypes.c_uint64),
            ('total_pagefile', ctypes.c_uint64),
            ('available_pagefile', ctypes.c_uint64),
            ('total_virtual', ctypes.c_uint64),
            ('available_virtual', ctypes.c_uint64),
            ('available_extended_virtual', ctypes.c_uint64),
        ]

    status = MemoryStatus()
    status.length = ctypes.sizeof(status)
    if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return status.total_physical
    return None


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--revision', default=None, help='Commit being benchmarked if git is not on PATH')
    args = parser.parse_args(argv)
    if not 3 <= args.repeats <= 20:
        parser.error('--repeats must be between 3 and 20')
    rows = []
    with TemporaryDirectory(prefix='sfile-benchmark-') as temporary:
        root = Path(temporary)
        app, password = prepare_demo(root / 'private')
        for size in (0, 1024, 1024 * 1024, 10 * 1024 * 1024):
            source = root / 'input.bin'
            source.write_bytes(b'x' * size)
            sends, receives, hashes = [], [], []
            for iteration in range(args.repeats):
                package, output = root / f'{size}-{iteration}.sfile', root / f'{size}-{iteration}.bin'
                start = perf_counter()
                sent = app.service.send_file(SendRequest('alice', 'bob', source, package, password))
                sends.append((perf_counter() - start) * 1000)
                if sent.status is not OperationStatus.SUCCESS:
                    raise RuntimeError('send failed')
                start = perf_counter()
                received = app.service.prepare_receive(ReceiveRequest('bob', package, password))
                if not received.prepared:
                    raise RuntimeError('receive failed')
                saved = app.service.save_received(received.prepared.handle, output)
                receives.append((perf_counter() - start) * 1000)
                if saved.status is not OperationStatus.SUCCESS:
                    raise RuntimeError('save failed')
                comparison = compare_files(source, output)
                if not comparison['equal']:
                    raise RuntimeError('content mismatch')
                hashes.append(comparison['actual_sha256'])
            rows.append({'bytes': size, 'send_ms': sends, 'receive_and_save_ms': receives,
                         'restored_sha256': hashes,
                         'median_send_ms': statistics.median(sends), 'median_receive_ms': statistics.median(receives)})
        app.service.close()
    print(json.dumps({'python': platform.python_version(), 'os': platform.platform(), 'cpu': platform.processor(),
                      'ram_bytes': _memory_bytes(), 'revision': args.revision or _revision(),
                      'cryptography': importlib.metadata.version('cryptography'),
                      'measurement': 'Includes encrypted key loading, crypto and disk IO; excludes key generation and dialogs.',
                      'repeats': args.repeats, 'results': rows}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
