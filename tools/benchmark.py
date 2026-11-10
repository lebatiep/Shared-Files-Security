"""Measure the Shamir 2-of-3 workflow with python -m tools.benchmark --repeats 3."""

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

from secure_share.config import MAX_FILE_BYTES
from secure_share.models import ContributionRequest, OperationStatus, ThresholdReceiveRequest, ThresholdSendRequest
from .compare_files import compare_files
from .demo_threshold import HOLDERS, SENDER, prepare_demo


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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--revision', default=None, help='Commit being benchmarked if git is not on PATH')
    args = parser.parse_args(argv)
    if not 3 <= args.repeats <= 20:
        parser.error('--repeats must be between 3 and 20')
    rows = []
    with TemporaryDirectory(prefix='sfile-benchmark-') as temporary:
        root = Path(temporary)
        app, passwords = prepare_demo(root / 'private')
        opener, contributor = HOLDERS[:2]
        try:
            for size in (0, 1024, 1024 * 1024, MAX_FILE_BYTES):
                source = root / 'input.bin'
                source.write_bytes(b'x' * size)
                sends, contributions, receives, hashes = [], [], [], []
                for iteration in range(args.repeats):
                    stem = f'{size}-{iteration}'
                    package = root / f'{stem}.sfile2'
                    approval = root / f'{stem}.sapproval'
                    output = root / f'{stem}.bin'
                    send_request = ThresholdSendRequest(SENDER, HOLDERS, source, package, passwords[SENDER])
                    contribution_request = ContributionRequest(
                        contributor, opener, package, approval, passwords[contributor]
                    )
                    receive_request = ThresholdReceiveRequest(opener, package, approval, passwords[opener])
                    start = perf_counter()
                    sent = app.service.send_threshold(send_request)
                    sends.append((perf_counter() - start) * 1000)
                    if sent.status is not OperationStatus.SUCCESS:
                        raise RuntimeError(f'package creation failed: {sent.error.code}')
                    start = perf_counter()
                    exported = app.service.export_contribution(contribution_request)
                    contributions.append((perf_counter() - start) * 1000)
                    if exported.status is not OperationStatus.SUCCESS:
                        raise RuntimeError(f'contribution export failed: {exported.error.code}')
                    start = perf_counter()
                    received = app.service.prepare_threshold_receive(receive_request)
                    if received.status is not OperationStatus.PREPARED:
                        raise RuntimeError(f'package opening failed: {received.error.code}')
                    saved = app.service.save_received(received.prepared.handle, output)
                    receives.append((perf_counter() - start) * 1000)
                    if saved.status is not OperationStatus.SUCCESS:
                        raise RuntimeError(f'plaintext save failed: {saved.error.code}')
                    comparison = compare_files(source, output)
                    if not comparison['equal']:
                        raise RuntimeError('content mismatch')
                    hashes.append(comparison['actual_sha256'])
                    for path in (package, approval, output):
                        path.unlink()
                rows.append({
                    'bytes': size,
                    'send_ms': sends,
                    'contribute_ms': contributions,
                    'receive_and_save_ms': receives,
                    'source_sha256': comparison['expected_sha256'],
                    'restored_sha256': hashes,
                    'median_send_ms': statistics.median(sends),
                    'median_contribute_ms': statistics.median(contributions),
                    'median_receive_ms': statistics.median(receives),
                })
        finally:
            app.service.close()
    print(json.dumps({'python': platform.python_version(), 'os': platform.platform(), 'cpu': platform.processor(),
                      'ram_bytes': _memory_bytes(), 'revision': args.revision or _revision(),
                      'cryptography': importlib.metadata.version('cryptography'),
                      'mode': 'shamir_2_of_3',
                      'measurement': ('Single machine with distinct profiles and passphrases. Timings include key loading, '
                                      'cryptography and disk I/O. They exclude key setup, dialogs and output comparison.'),
                      'repeats': args.repeats, 'results': rows}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
