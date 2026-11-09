"""Run with: python -m tools.benchmark --repeats 3."""

import argparse
import importlib.metadata
import json
from pathlib import Path
import platform
import statistics
from tempfile import TemporaryDirectory
from time import perf_counter

from secure_share.models import OperationStatus, ReceiveRequest, SendRequest
from .demo import prepare_demo


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--repeats', type=int, default=3)
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
            sends, receives = [], []
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
                if saved.status is not OperationStatus.SUCCESS or output.read_bytes() != source.read_bytes():
                    raise RuntimeError('content mismatch')
            rows.append({'bytes': size, 'send_ms': sends, 'receive_and_save_ms': receives,
                         'median_send_ms': statistics.median(sends), 'median_receive_ms': statistics.median(receives)})
        app.service.close()
    print(json.dumps({'python': platform.python_version(), 'os': platform.system(), 'cpu': platform.processor(),
                      'cryptography': importlib.metadata.version('cryptography'),
                      'measurement': 'Includes encrypted key loading, crypto and disk IO; excludes key generation and dialogs.',
                      'repeats': args.repeats, 'results': rows}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
