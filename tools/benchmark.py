"""Measure the Shamir 2-of-3 file-sharing workflow."""

import argparse
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
from tempfile import TemporaryDirectory
from time import perf_counter

from secure_share.config import MAX_FILE_BYTES
from secure_share.models import (
    ContributionRequest,
    OperationStatus,
    ThresholdReceiveRequest,
    ThresholdSendRequest,
)
from .compare_files import compare_files
from .demo_threshold import HOLDERS, SENDER, prepare_demo


SHAMIR = 'shamir_2_of_3'


def _git(*args):
    root = Path(__file__).resolve().parents[1]
    try:
        return subprocess.check_output(
            ['git', '-c', f'safe.directory={root.as_posix()}', *args],
            cwd=root, text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


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


def _expect(result, status, step):
    if result.status is not status:
        detail = result.error.code if result.error else result.status
        raise RuntimeError(f'{step} failed: {detail}')


def _run_trial(service, passwords, source, stem):
    opener, contributor = HOLDERS[:2]
    output = source.with_name(f'{stem}.bin')
    package = source.with_name(f'{stem}.sfile2')
    approval = source.with_name(f'{stem}.sapproval')
    send_request = ThresholdSendRequest(SENDER, HOLDERS, source, package, passwords[SENDER])
    contribution_request = ContributionRequest(contributor, opener, package, approval, passwords[contributor])
    receive_request = ThresholdReceiveRequest(opener, package, approval, passwords[opener])

    start = perf_counter()
    sent = service.send_threshold(send_request)
    send_ms = (perf_counter() - start) * 1000
    _expect(sent, OperationStatus.SUCCESS, 'Package creation')

    start = perf_counter()
    exported = service.export_contribution(contribution_request)
    contribute_ms = (perf_counter() - start) * 1000
    _expect(exported, OperationStatus.SUCCESS, 'Contribution export')

    start = perf_counter()
    received = service.prepare_threshold_receive(receive_request)
    _expect(received, OperationStatus.PREPARED, 'Package opening')
    saved = service.save_received(received.prepared.handle, output)
    receive_ms = (perf_counter() - start) * 1000
    _expect(saved, OperationStatus.SUCCESS, 'Plaintext save')

    comparison = compare_files(source, output)
    if not comparison['equal'] or comparison['actual_sha256'] != comparison['expected_sha256']:
        raise RuntimeError('Recovered file differs from the source')
    trial = {
        'send_ms': send_ms,
        'contribute_ms': contribute_ms,
        'receive_and_save_ms': receive_ms,
        'total_ms': send_ms + contribute_ms + receive_ms,
        'package_bytes': package.stat().st_size,
        'contribution_bytes': approval.stat().st_size,
        'source_sha256': comparison['expected_sha256'],
        'restored_sha256': comparison['actual_sha256'],
    }
    for path in (package, approval, output):
        path.unlink()
    return trial


def _summarize(trials):
    sends = [trial['send_ms'] for trial in trials]
    contributions = [trial['contribute_ms'] for trial in trials]
    receives = [trial['receive_and_save_ms'] for trial in trials]
    totals = [trial['total_ms'] for trial in trials]
    package_sizes = [trial['package_bytes'] for trial in trials]
    contribution_sizes = [trial['contribution_bytes'] for trial in trials]
    return {
        'send_ms': sends,
        'contribute_ms': contributions,
        'receive_and_save_ms': receives,
        'total_ms': totals,
        'package_bytes': package_sizes,
        'contribution_bytes': contribution_sizes,
        'source_sha256': trials[0]['source_sha256'],
        'restored_sha256': [trial['restored_sha256'] for trial in trials],
        'median_send_ms': statistics.median(sends),
        'median_contribute_ms': statistics.median(contributions),
        'median_receive_ms': statistics.median(receives),
        'median_total_ms': statistics.median(totals),
        'median_package_bytes': statistics.median(package_sizes),
        'median_contribution_bytes': statistics.median(contribution_sizes),
    }


def _measure_size(service, passwords, source, size, repeats):
    source.write_bytes(b'x' * size)
    trials = [_run_trial(service, passwords, source, f'{size}-{iteration}') for iteration in range(repeats)]
    return {'bytes': size, **_summarize(trials)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--revision', default=None, help='Commit being benchmarked if git is not on PATH')
    parser.add_argument('--output', type=Path, help='Also write the JSON report to this path')
    args = parser.parse_args(argv)
    if not 3 <= args.repeats <= 20:
        parser.error('--repeats must be between 3 and 20')

    revision = args.revision or _git('rev-parse', 'HEAD') or os.environ.get('GITHUB_SHA')
    status = _git('status', '--porcelain')
    with TemporaryDirectory(prefix='sfile-benchmark-') as temporary:
        root = Path(temporary)
        app, passwords = prepare_demo(root / 'private')
        try:
            rows = [
                _measure_size(app.service, passwords, root / 'input.bin', size, args.repeats)
                for size in (0, 1024, 1024 * 1024, MAX_FILE_BYTES)
            ]
        finally:
            app.service.close()

    report = {
        'python': platform.python_version(),
        'os': platform.platform(),
        'cpu': platform.processor(),
        'ram_bytes': _memory_bytes(),
        'revision': revision,
        'working_tree_dirty': bool(status) if status is not None else None,
        'crypto_backend': 'pure-python',
        'mode': SHAMIR,
        'measurement': (
            'One machine with separate profiles. Timings include key loading, cryptography and disk I/O. '
            'They exclude profile creation, dialogs, transport and output comparison. Total time sums the measured '
            'phases of each trial. File sizes describe one package and one contribution.'
        ),
        'warmups_per_mode_per_size': 0,
        'repeats': args.repeats,
        'results': rows,
    }
    encoded = json.dumps(report, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded + '\n', encoding='utf-8')
    print(encoded)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
