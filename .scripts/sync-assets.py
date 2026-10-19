#!/usr/bin/env python3
"""Refresh committed CLI assets from normative inputs; never run by Curator."""

from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = (
    "spec/kernel/schemas/*.json",
    "spec/kernel/vectors/semantic/*.json",
    "spec/domains/decisions/assumption.json", "spec/domains/decisions/decision.json",
    "spec/domains/decisions/decision_proposal.json", "spec/domains/decisions/rule.json",
    "spec/domains/profiles-synthetic/*.json",
)


def main():
    target = ROOT / "go/assets"
    expected = {p.relative_to(ROOT): p for pattern in PATTERNS for p in ROOT.glob(pattern)}
    for name in ("passing.txt", "passing-ops.txt"):
        expected[Path("conformance") / name] = ROOT / "go/conformance" / name
    for directory in (target / "spec", target / "conformance"):
        if directory.exists():
            for path in directory.rglob("*"):
                if path.is_file() and path.relative_to(target) not in expected:
                    path.unlink()
    copied = 0
    try:
        for relative, source in sorted(expected.items()):
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            copied += 1
    except OSError as error:
        raise SystemExit(f"asset synchronization failed after {copied} files: {error}") from error
    print(f"Synced {len(expected)} embedded asset files")


if __name__ == "__main__":
    main()
