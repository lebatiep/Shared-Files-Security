"""Run with python -m tools.demo_threshold. All profiles and files are temporary."""

from itertools import combinations
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

from secure_share.application import create_application
from secure_share.errors import ErrorCode
from secure_share.models import ContributionRequest, OperationStatus, ThresholdReceiveRequest, ThresholdSendRequest

SENDER = "tiep"
HOLDERS = ("nhat-minh", "hoang", "viet")
DISPLAY_NAMES = {SENDER: "Tiêp", "nhat-minh": "Nhật Minh", "hoang": "Hoàng", "viet": "Việt"}


def prepare_demo(root):
    app = create_application(root)
    passwords = {name: f"threshold-demo-only-{name}".encode("ascii") for name in (SENDER, *HOLDERS)}
    for name, password in passwords.items():
        app.keys.create_profile(name, DISPLAY_NAMES[name], password)
    for owner in passwords:
        for peer in passwords:
            if owner == peer:
                continue
            profile = app.keys.get_profile(peer)
            app.trust.import_contact(owner, peer, app.keys.public_bundle(peer))
            app.trust.verify_contact(owner, peer, profile.encryption_fingerprint, profile.signing_fingerprint)
    return app, passwords


def run_demo(root):
    root = Path(root)
    app, passwords = prepare_demo(root / "private")
    try:
        source, package = root / "survey.txt", root / "survey.sfile2"
        data = "Dữ liệu khảo sát giả cho demo 2-trên-3.\n".encode("utf-8")
        source.write_bytes(data)
        sent = app.service.send_threshold(ThresholdSendRequest(SENDER, HOLDERS, source, package, passwords[SENDER]))
        outcomes = {"package_created": sent.status is OperationStatus.SUCCESS}
        if not outcomes["package_created"]:
            return outcomes

        first_holder = HOLDERS[0]
        alone = app.service.prepare_threshold_receive(
            ThresholdReceiveRequest(first_holder, package, root / "missing.sapproval", passwords[first_holder])
        )
        outcomes["one_holder_blocked"] = bool(alone.error and alone.error.code is ErrorCode.READ_FAILED)
        for opener, contributor in combinations(HOLDERS, 2):
            label = f"{opener}_and_{contributor}"
            approval = root / f"{label}.sapproval"
            output = root / f"{label}.txt"
            exported = app.service.export_contribution(
                ContributionRequest(contributor, opener, package, approval, passwords[contributor])
            )
            outcomes[label] = False
            if exported.status is not OperationStatus.SUCCESS:
                continue
            opened = app.service.prepare_threshold_receive(
                ThresholdReceiveRequest(opener, package, approval, passwords[opener])
            )
            if opened.status is not OperationStatus.PREPARED:
                continue
            saved = app.service.save_received(opened.prepared.handle, output)
            outcomes[label] = saved.status is OperationStatus.SUCCESS and output.read_bytes() == data
        return outcomes
    finally:
        app.service.close()


def main():
    with TemporaryDirectory(prefix="sfile-threshold-demo-") as temporary:
        outcomes = run_demo(temporary)
    labels = {
        f"{first}_and_{second}": f"{DISPLAY_NAMES[first]} và {DISPLAY_NAMES[second]}"
        for first, second in combinations(HOLDERS, 2)
    }
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps({**outcomes, "participants": DISPLAY_NAMES, "pairs": labels}, ensure_ascii=False, indent=2))
    return 0 if all(outcomes.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
