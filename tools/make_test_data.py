"""Create synthetic files for demo and size-boundary tests."""

import argparse
import json
from pathlib import Path

from secure_share.config import MAX_FILE_BYTES


def _write_pattern(stream, size):
    block = bytes(range(256)) * 256
    while size:
        count = min(size, len(block))
        stream.write(block[:count])
        size -= count


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    contents = {
        'empty.bin': b'',
        'Dữ liệu mẫu.txt': 'Dữ liệu tổng hợp dùng để kiểm thử.\n'.encode('utf-8'),
        'binary.bin': bytes(range(256)),
        '1KiB.bin': 1024,
        '1MiB.bin': 1024 * 1024,
        '10MiB-minus-1.bin': MAX_FILE_BYTES - 1,
        '10MiB.bin': MAX_FILE_BYTES,
        '10MiB-plus-1.bin': MAX_FILE_BYTES + 1,
    }
    args.out.mkdir(parents=True, exist_ok=True)
    if any((args.out / name).exists() for name in contents):
        parser.error('Choose an output folder without existing test files')
    result = []
    for name, content in contents.items():
        path = args.out / name
        with path.open('xb') as stream:
            if isinstance(content, bytes):
                stream.write(content)
            else:
                _write_pattern(stream, content)
        result.append({'file': str(path), 'bytes': path.stat().st_size})
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
