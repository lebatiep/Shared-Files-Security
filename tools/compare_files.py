"""Compare byte counts, SHA-256 and contents without printing file data."""

import argparse
import json
from pathlib import Path

from secure_share.crypto_ops import SHA256


def compare_files(expected, actual):
    expected_hash, actual_hash = SHA256(), SHA256()
    expected_bytes = actual_bytes = 0
    equal = True
    with Path(expected).open('rb') as left, Path(actual).open('rb') as right:
        while True:
            left_block, right_block = left.read(65536), right.read(65536)
            if not left_block and not right_block:
                break
            expected_bytes += len(left_block)
            actual_bytes += len(right_block)
            expected_hash.update(left_block)
            actual_hash.update(right_block)
            if left_block != right_block:
                equal = False
    return {
        'equal': equal,
        'expected_bytes': expected_bytes,
        'actual_bytes': actual_bytes,
        'expected_sha256': expected_hash.digest().hex(),
        'actual_sha256': actual_hash.digest().hex(),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('expected', type=Path)
    parser.add_argument('actual', type=Path)
    args = parser.parse_args(argv)
    result = compare_files(args.expected, args.actual)
    print(json.dumps(result, indent=2))
    return 0 if result['equal'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
