"""Run with: python -m tools.case_report

Lists which of the 60 acceptance IDs have tests linked by @pytest.mark.case.
It only collects tests; it does not run them and never marks a case as passed.
A linked unit test does not replace the independent run of that case.
"""

import contextlib
import io
import sys

import pytest

GROUPS = {
    'I': 10, 'S': 9, 'R': 7, 'A': 12, 'P': 8, 'O': 8, 'L': 6,
}
ALL_IDS = [f'{letter}{number:02d}' for letter, count in GROUPS.items() for number in range(1, count + 1)]


class _Collector:
    def __init__(self):
        self.items = []

    def pytest_collection_modifyitems(self, items):
        self.items = list(items)


def linked_cases():
    collector = _Collector()
    with contextlib.redirect_stdout(io.StringIO()):
        pytest.main(['--collect-only', '-q', '-p', 'no:cacheprovider'], plugins=[collector])
    linked = {case: [] for case in ALL_IDS}
    unknown = set()
    for item in collector.items:
        for marker in item.iter_markers('case'):
            for case in marker.args:
                if case in linked:
                    linked[case].append(item.nodeid.split('::', 1)[-1])
                else:
                    unknown.add(case)
    return linked, unknown


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    linked, unknown = linked_cases()
    covered = [case for case in ALL_IDS if linked[case]]
    print('| ID | Linked tests | Test names |')
    print('|---|---|---|')
    for case in ALL_IDS:
        names = sorted(set(name.split('[')[0] for name in linked[case]))
        print(f"| {case} | {len(linked[case])} | {'; '.join(names) if names else '(none)'} |")
    print(f'\n{len(covered)} of {len(ALL_IDS)} IDs have at least one linked test (collected, not executed).')
    if unknown:
        print('Unknown IDs in markers:', ', '.join(sorted(unknown)))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
