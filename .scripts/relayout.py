#!/usr/bin/env python3
"""Replay the complete packaging change, or verify it against a committed tree.

WARNING: Run only in a clean, disposable clone.
Recovery from an interrupted run is a fresh clone; rerunning is not recovery.

Copy .scripts/ to a clean pre-layout checkout, then run this entrypoint there.
All changes are prepared in a sibling staging tree, then published atomically.
Refusals leave the original tree unchanged; upstream edits use a context patch.
"""

import argparse
import ctypes
import importlib.util
import io
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REPLAY_FILES = ("move-go-module.py", "sync-assets.py", "relayout.py",
                "relayout-test.py", "packaging.patch")


def git(root, *args, check=True):
    env = dict(os.environ, GIT_WORK_TREE=str(root))
    return subprocess.run(["git", *args], cwd=root, env=env, check=check,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def prepare(root):
    subprocess.run([sys.executable, "-B", str(root / ".scripts/move-go-module.py")], check=True)
    patch = str(root / ".scripts/packaging.patch")
    if git(root, "apply", "--reverse", "--check", patch, check=False).returncode:
        result = git(root, "apply", "--check", patch, check=False)
        if result.returncode:
            raise SystemExit("packaging patch conflict; review upstream edits:\n" + result.stderr.decode())
        git(root, "apply", patch)
    subprocess.run([sys.executable, "-B", str(root / ".scripts/sync-assets.py")], check=True)


# These existing operational entries are moved intact only at publication. They
# are never traversed/copied (in particular Git metadata and private temp files).
PRESERVE = {".git", ".temp", "bin", "__pycache__"}


def atomic_exchange(left, right):
    """Exchange sibling filesystem trees atomically, or fail without changing them."""
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        exchange = libc.renamex_np
        exchange.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        args = [os.fsencode(left), os.fsencode(right), 2]  # RENAME_SWAP
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        exchange = libc.renameat2
        exchange.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                             ctypes.c_char_p, ctypes.c_uint]
        args = [-100, os.fsencode(left), -100, os.fsencode(right), 2]  # RENAME_EXCHANGE
    else:
        raise SystemExit("atomic directory exchange unavailable on this platform")
    exchange.restype = ctypes.c_int
    if exchange(*args) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


class RecoveryRequired(RuntimeError):
    """Keep staging intact if the filesystem cannot restore a parked entry."""


def publish(root, stage):
    """Publish in one exchange; roll back a reported publication failure."""
    parked = []
    exchanged = False
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
    try:
        for name in sorted(PRESERVE):
            source = root / name
            if source.exists() or source.is_symlink():
                source.rename(stage / name)
                parked.append(name)
        atomic_exchange(root, stage)
        exchanged = True
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    except BaseException:
        try:
            if exchanged:
                atomic_exchange(root, stage)
            for name in reversed(parked):
                (stage / name).rename(root / name)
        except BaseException as error:
            raise RecoveryRequired(f"filesystem rollback failed; retain recovery tree {stage}: {error}") from error
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        raise


def replay(root):
    root = root.resolve()
    spec = importlib.util.spec_from_file_location("move_module", root / ".scripts/move-go-module.py")
    move = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(move)
    move.plan(root)  # Refuse unclassified inputs before reading any of their bytes.
    before = inventory(root, directories=True, omit=PRESERVE)
    if any(value[0] == "symlink" for value in before.values()):
        raise SystemExit("source payload symlink requires review before relocation")
    # A sibling is required: a directory cannot be exchanged with its descendant.
    # No .temp, Git metadata or build output is copied into this staging tree.
    scratch = Path(tempfile.mkdtemp(prefix=f".{root.name}-relayout-", dir=root.parent))
    stage = scratch / "tree"
    committed = False
    recovery_required = False
    try:
        shutil.copytree(root, stage, symlinks=True,
                        ignore=lambda directory, names: PRESERVE if Path(directory) == root else ())
        prepare(stage)
        # Verify the host/filesystem primitive before parking any original entry.
        left, right = scratch / "exchange-a", scratch / "exchange-b"
        left.mkdir()
        right.mkdir()
        (left / "marker").write_text("left")
        (right / "marker").write_text("right")
        atomic_exchange(left, right)
        if (left / "marker").read_text() != "right" or (right / "marker").read_text() != "left":
            raise SystemExit("atomic directory exchange failed its control")
        if before != inventory(root, directories=True, omit=PRESERVE):
            raise SystemExit("source tree changed during staging; refusing publication")
        publish(root, stage)
        committed = True
    except RecoveryRequired:
        recovery_required = True
        raise
    finally:
        # On success stage is the old source, with operational entries moved out.
        # On preflight failure it is just the disposable prospective result.
        if not recovery_required:
            try:
                shutil.rmtree(scratch)
            except OSError as error:
                if not committed:
                    raise
                print(f"replay committed; staging cleanup deferred at {scratch}: {error}", file=sys.stderr)


def archive(root, tree, destination):
    data = git(root, "archive", tree).stdout
    with tarfile.open(fileobj=io.BytesIO(data)) as stream:
        for member in stream:
            name = Path(member.name)
            if name.is_absolute() or ".." in name.parts or not (member.isfile() or member.isdir()):
                raise SystemExit(f"unsupported archive entry: {member.name}")
            target = destination / name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(stream.extractfile(member).read())
                target.chmod(member.mode)


def inventory(root, directories=False, omit=(".temp",)):
    """Read a tree without following symlinks or entering omitted root entries."""
    result = {}

    def visit(directory, relative):
        if directories:
            result[relative or "."] = ("directory", stat.S_IMODE(directory.stat().st_mode))
        for path in sorted(directory.iterdir()):
            if not relative and path.name in omit:
                continue
            name = f"{relative}/{path.name}" if relative else path.name
            mode = stat.S_IMODE(path.lstat().st_mode)
            if path.is_symlink():
                result[name] = ("symlink", os.readlink(path), mode)
            elif path.is_dir():
                visit(path, name)
            elif path.is_file():
                result[name] = ("file", path.read_bytes(), mode)
            else:
                raise SystemExit(f"unsupported source entry: {name}")

    visit(root, "")
    return result


def check(base, expected):
    scratch = ROOT / ".temp"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="relayout-check-", dir=scratch) as name:
        directory = Path(name)
        source, target = directory / "source", directory / "expected"
        source.mkdir()
        target.mkdir()
        archive(ROOT, base, source)
        archive(ROOT, expected, target)
        (source / ".scripts").mkdir(exist_ok=True)
        for name in REPLAY_FILES:
            shutil.copyfile(ROOT / ".scripts" / name, source / ".scripts" / name)
        replay(source)
        first = inventory(source)
        replay(source)
        if first != inventory(source):
            raise SystemExit("replay is not byte/mode idempotent")
        # Git records only executable status, not the checkout's umask-derived
        # permission bits. Refusal and rerun checks above retain every mode bit.
        def git_modes(entries):
            return {name: (*value[:-1], bool(value[-1] & 0o111))
                    for name, value in entries.items()}

        actual, want = git_modes(first), git_modes(inventory(target))
        differences = sorted(name for name in actual.keys() | want.keys() if actual.get(name) != want.get(name))
        if differences:
            raise SystemExit("replay differs from expected tree:\n" + "\n".join(differences))
        print(f"Replay {base} equals {expected}: {len(want)} files, bytes and executable modes; rerun identical")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", metavar="BASE", help="replay BASE in scratch and compare with --expected")
    parser.add_argument("--expected", default="HEAD", help="committed tree/ref to compare (default HEAD)")
    args = parser.parse_args()
    if args.check:
        check(args.check, args.expected)
    else:
        replay(ROOT)
