"""List acceptance tests, or execute them and write per-variant evidence."""

import argparse
import contextlib
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

import pytest

GROUPS = {
    "I": 10, "S": 9, "R": 7, "A": 12, "P": 8, "O": 8, "L": 6,
}
ALL_IDS = [f"{letter}{number:02d}" for letter, count in GROUPS.items() for number in range(1, count + 1)]
ROOT = Path(__file__).resolve().parents[1]
OUTCOME_ORDER = ("failed", "xpassed", "xfailed", "skipped", "not_run", "passed")


class _Evidence:
    def __init__(self):
        self.linked = {case: [] for case in ALL_IDS}
        self.invalid_markers = []
        self.phases = {}
        self.subtests = {}

    @pytest.hookimpl(trylast=True)
    def pytest_collection_modifyitems(self, items):
        for item in items:
            for marker in item.iter_markers("case"):
                if not marker.args or marker.kwargs:
                    self.invalid_markers.append({"test": item.nodeid, "reason": "expected positional case IDs"})
                for case in marker.args:
                    if not isinstance(case, str) or case not in self.linked:
                        self.invalid_markers.append({"test": item.nodeid, "reason": f"unknown case ID {case!r}"})
                    elif item.nodeid not in self.linked[case]:
                        self.linked[case].append(item.nodeid)

    def pytest_runtest_logreport(self, report):
        if hasattr(report, "wasxfail"):
            outcome = "xfailed" if report.skipped else "xpassed"
        else:
            outcome = report.outcome
        result = {
            "outcome": outcome,
            "seconds": round(report.duration, 6),
        }
        if hasattr(report, "context"):
            subtests = self.subtests.setdefault(report.nodeid, [])
            subtests.append({"index": len(subtests) + 1, **result})
            return
        phases = self.phases.setdefault(report.nodeid, {})
        if report.when in phases:
            previous = phases[report.when]["outcome"]
            if OUTCOME_ORDER.index(previous) < OUTCOME_ORDER.index(outcome):
                return
        phases[report.when] = result

    def variants(self, case):
        return [
            {"test": test, "outcome": _outcome(self.phases.get(test, {}), self.subtests.get(test, [])),
             "phases": self.phases.get(test, {}), "subtests": self.subtests.get(test, [])}
            for test in self.linked[case]
        ]


def _outcome(phases, subtests):
    outcomes = {result["outcome"] for result in [*phases.values(), *subtests]}
    if phases.keys() != {"setup", "call", "teardown"}:
        outcomes.add("not_run")
    return min(outcomes, key=OUTCOME_ORDER.index)


def _git(*args):
    try:
        result = subprocess.run(
            ["git", "-c", f"safe.directory={ROOT.as_posix()}", *args],
            cwd=ROOT, capture_output=True, text=True, timeout=5, check=True,
        )
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _metadata():
    status = _git("status", "--porcelain")
    return {
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "os": platform.system(),
        "os_release": platform.release(),
        "python": platform.python_version(),
        "pytest": pytest.__version__,
        "commit": _git("rev-parse", "HEAD"),
        "working_tree_dirty": bool(status) if status is not None else None,
        "runner": os.environ.get("RUNNER_OS", "local"),
        "github_run_id": os.environ.get("GITHUB_RUN_ID"),
        "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
    }


def _display(cases, run):
    print("| ID | Linked tests | Actual outcomes | Test names |")
    print("|---|---|---|---|")
    for case, variants in cases.items():
        names = sorted({variant["test"].split("::", 1)[-1].split("[", 1)[0] for variant in variants})
        outcomes = sorted({variant["outcome"] for variant in variants})
        print(f"| {case} | {len(variants)} | {', '.join(outcomes) or 'missing'} | {'; '.join(names) or '-'} |")
    linked_count = sum(bool(variants) for variants in cases.values())
    print(f"\n{linked_count}/{len(ALL_IDS)} IDs have at least one linked test.")
    if run:
        passed = sum(
            bool(variants) and all(variant["outcome"] == "passed" for variant in variants)
            for variants in cases.values()
        )
        print(f"{passed}/{len(ALL_IDS)} IDs had every linked automated test pass in this run.")
    else:
        print("Collection only. Test results require --run.")
    print("Automated evidence is separate from independent review and manual acceptance.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="execute the full suite and check linked outcomes")
    parser.add_argument("--json", type=Path, metavar="PATH", help="write the machine-readable report")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    evidence = _Evidence()
    metadata = _metadata()
    pytest_args = ["-q", "-p", "no:cacheprovider", str(ROOT / "tests")]
    if args.run:
        code = pytest.main(pytest_args, plugins=[evidence])
    else:
        with contextlib.redirect_stdout(io.StringIO()) as collection:
            code = pytest.main(["--collect-only", *pytest_args], plugins=[evidence])
        if code:
            print(collection.getvalue())

    cases = {case: evidence.variants(case) for case in ALL_IDS}
    missing = [case for case, variants in cases.items() if not variants]
    nonpassing = [
        case for case, variants in cases.items()
        if args.run and any(variant["outcome"] != "passed" for variant in variants)
    ]
    _display(cases, args.run)
    if missing:
        print("Missing case IDs:", ", ".join(missing))
    if nonpassing:
        print("Case IDs with non-passing linked tests:", ", ".join(nonpassing))
    for marker in evidence.invalid_markers:
        print(f"Invalid case marker in {marker['test']}: {marker['reason']}")

    if args.json is not None:
        report = {
            "schema_version": 1,
            "mode": "automated_run" if args.run else "collection",
            "metadata": metadata,
            "pytest_exit_code": int(code),
            "missing_case_ids": missing,
            "nonpassing_case_ids": nonpassing,
            "invalid_markers": evidence.invalid_markers,
            "cases": cases,
        }
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return int(code) or int(bool(missing or nonpassing or evidence.invalid_markers))


if __name__ == "__main__":
    raise SystemExit(main())
