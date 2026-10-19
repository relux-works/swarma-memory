#!/usr/bin/env python3
"""Bounded replay controls on an isolated archive; no commits or network."""

import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

spec = importlib.util.spec_from_file_location("relayout", Path(__file__).with_name("relayout.py"))
layout = importlib.util.module_from_spec(spec)
spec.loader.exec_module(layout)
ROOT = layout.ROOT


def run(root, *command, ok=True, contains=None):
    result = subprocess.run(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    text = result.stdout.decode()
    if (result.returncode == 0) != ok or (contains and contains not in text):
        raise AssertionError(f"{command}: exit {result.returncode}\n{text}")
    print(f"exit={result.returncode} {' '.join(command)}\n{text}", flush=True)
    return text


def scripts(root):
    (root / ".scripts").mkdir(exist_ok=True)
    for name in layout.REPLAY_FILES:
        shutil.copyfile(ROOT / ".scripts" / name, root / ".scripts" / name)


def refusals(root, base):
    # These full-entrypoint plants require specific failures and an identical
    # original tree, including empty directories, symlinks and permission bits.
    for control in ("collision", "unknown", "patch", "mid-sync", "publish"):
        fixture = root / control
        fixture.mkdir()
        layout.archive(ROOT, base, fixture)
        scripts(fixture)
        (fixture / ".temp/empty").mkdir(parents=True)
        marker = fixture / ".temp/marker.txt"
        marker.write_text("preserve ignored input\n")
        marker.chmod(0o640)
        (fixture / "bin").mkdir()
        (fixture / "bin/marker-link").symlink_to("../.temp/marker.txt")
        if control == "collision":
            (fixture / "go/kernel").mkdir(parents=True)
            (fixture / "go/kernel/marker.txt").write_text("existing\n")
            diagnostic = "refusing conflicting relocation: kernel and go/kernel"
        elif control == "unknown":
            (fixture / "unclassified.txt").write_text("unknown input\n")
            diagnostic = "unclassified root input: unclassified.txt"
        elif control == "patch":
            source = fixture / "cmd/memory/main.go"
            text = source.read_text()
            old = 'dir := "spec/kernel/vectors/semantic"'
            assert old in text, "patch-conflict plant was not applied"
            source.write_text(text.replace(old, 'dir := "upstream/vectors"'))
            diagnostic = "packaging patch conflict; review upstream edits:"
        elif control == "mid-sync":
            (fixture / "conformance/passing.txt").unlink()
            diagnostic = "asset synchronization failed after 1 files:"
        else:
            # Bounded injected publication syscall failure exercises rollback of
            # ignored entries; the capability probe still uses the real syscall.
            diagnostic = "publication control failure"
        before = layout.inventory(fixture, directories=True, omit=())
        if control == "publish":
            code = """import importlib.util
from pathlib import Path
s = importlib.util.spec_from_file_location('r', '.scripts/relayout.py')
r = importlib.util.module_from_spec(s)
s.loader.exec_module(r)
root = Path.cwd()
exchange = r.atomic_exchange
def fail_publication(left, right):
    if left == root:
        raise OSError('publication control failure')
    return exchange(left, right)
r.atomic_exchange = fail_publication
r.replay(root)
"""
            command = [sys.executable, "-B", "-c", code]
        else:
            command = [sys.executable, "-B", str(fixture / ".scripts/relayout.py")]
        run(fixture, *command, ok=False, contains=diagnostic)
        assert before == layout.inventory(fixture, directories=True, omit=()), control + " partially changed inputs"
        assert not list(root.glob(f".{fixture.name}-relayout-*")), "staging tree was not cleaned"
        print(control + ": zero path/byte/mode changes", flush=True)


def main(base):
    scratch = ROOT / ".temp"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="relayout-controls-", dir=scratch) as directory:
        root = Path(directory)
        help_text = run(ROOT, sys.executable, "-B", str(ROOT / ".scripts/relayout.py"), "--help")
        # Usage must disclose the accepted interruption limit of this migration.
        help_text = " ".join(help_text.split())
        assert "clean, disposable clone" in help_text
        assert "interrupted run is a fresh clone" in help_text
        refusals(root, base)
        # A valid newer package and actual importer must both survive the replay.
        newer = root / "newer"
        newer.mkdir()
        layout.archive(ROOT, base, newer)
        scripts(newer)
        has_gate = "CLI end-to-end gate" in (newer / ".github/workflows/ci.yml").read_text()
        (newer / "extra").mkdir()
        (newer / "extra/extra.go").write_text('package extra\nconst Value = "preserved"\n')
        (newer / "e2e").mkdir(exist_ok=True)
        (newer / "e2e/extra_test.go").write_text('''package e2e_test
import (
    "testing"
    "github.com/relux-works/swarma-memory/extra"
    "github.com/relux-works/swarma-memory"
)
func TestExtra(t *testing.T) { if extra.Value != "preserved" || memoryassets.RootValue != "root preserved" { t.Fatal(extra.Value) } }
''')
        (newer / "root_extra_test.go").write_text('package memoryassets\n// Root Go files must move too.\n')
        (newer / "root_extra.go").write_text('package memoryassets\nconst RootValue = "root preserved"\n')
        (newer / "extra/fixture.txt").write_text("package input\n")
        with (newer / "cmd/memory/main.go").open("a") as stream:
            stream.write("\n// New upstream CLI comment must survive packaging.\n")
        with (newer / "docs/cli.md").open("a") as stream:
            stream.write("\nNew upstream documentation must survive packaging.\n")
        run(newer, "go", "test", "-count=1", "-run", "^TestExtra$", "./extra", "./e2e")
        # Ignored operational files and symlinks survive successful publication.
        (newer / ".temp/empty").mkdir(parents=True)
        marker = newer / ".temp/marker.txt"
        marker.write_text("preserved operational state\n")
        marker.chmod(0o640)
        (newer / "bin").mkdir()
        (newer / "bin/link").symlink_to("../.temp/marker.txt")
        operational = {name: layout.inventory(newer / name, directories=True, omit=())
                       for name in (".temp", "bin")}
        # The existing root package must stay together below go/assets/.
        run(newer, sys.executable, "-B", str(newer / ".scripts/relayout.py"))
        if has_gate:
            # A real upstream e2e step must survive and run in the relocated module.
            assert "run: go -C go test -count=1 -v ./e2e" in (newer / ".github/workflows/ci.yml").read_text()
        for name, wanted in operational.items():
            assert wanted == layout.inventory(newer / name, directories=True, omit=())
        assert (newer / "go/extra/fixture.txt").read_text() == "package input\n"
        assert (newer / "go/assets/root_extra_test.go").exists()
        assert "New upstream CLI comment" in (newer / "go/cmd/memory/main.go").read_text()
        assert "New upstream documentation" in (newer / "docs/cli.md").read_text()
        before = layout.inventory(newer)
        run(newer, sys.executable, "-B", str(newer / ".scripts/relayout.py"))
        assert before == layout.inventory(newer), "rerun changed bytes/modes"
        run(newer, "go", "-C", "go", "build", "./cmd/memory")
        run(newer, "go", "-C", "go", "test", "-count=1", "./...")
        # A known bad comparison target establishes check mode fails closed.
        run(ROOT, sys.executable, "-B", str(ROOT / ".scripts/relayout.py"),
            "--check", base, "--expected", base, ok=False,
            contains="replay differs from expected tree:")
        print("Replay controls passed: newer-base positive, idempotence, all-or-nothing refusals, publication rollback, check-mode negative")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: relayout-test.py PRE_LAYOUT_BASE")
    main(sys.argv[1])
