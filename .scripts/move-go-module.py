#!/usr/bin/env python3
"""Mechanical relocation; relayout.py supplies the complete packaging replay."""

from pathlib import Path
import argparse
import re

OLD = "github.com/relux-works/swarma-memory"
NEW = OLD + "/go"
# Normative sources, prose and packaging remain outside the module. Scratch and
# build output are ignored, never classified as first-party source inputs.
KEEP = {"spec", "docs", ".github", ".scripts", "README.md", "LICENSE", "NOTICE",
        "UNRESOLVED_QUESTIONS.md", "SKILL.md", "agent-skill.json", ".gitignore",
        ".gitattributes", ".git", ".temp", "bin", "__pycache__", "go"}


def plan(root):
    """Classify and check all root inputs without changing or reading their bytes."""
    moves = []
    for source in sorted(root.iterdir()):
        if source.name in KEEP:
            continue
        if source.is_symlink():
            raise SystemExit(f"unclassified root symlink: {source.name}")
        if source.suffix == ".go":
            target = "go/assets/" + source.name
        elif source.name in {"go.mod", "go.sum"}:
            target = "go/" + source.name
        elif source.is_dir() and any(source.rglob("*.go")):
            target = "go/" + source.name
        else:
            raise SystemExit(f"unclassified root input: {source.name}; classify before relocation")
        if (root / target).exists():
            raise SystemExit(f"refusing conflicting relocation: {source.name} and {target}")
        moves.append((source, root / target))
    return moves


def relocate(root):
    moves = plan(root)
    if not moves:
        return
    packages = {source.name for source, _ in moves if source.is_dir()}
    # Include already moved packages so reruns preserve the same prose mapping.
    if (root / "go").exists():
        packages.update(p.name for p in (root / "go").iterdir() if p.is_dir() and p.name != "assets")
    for source, target in moves:
        target.parent.mkdir(parents=True, exist_ok=True)
        source.rename(target)
    for path in (root / "go").rglob("*.go"):
        text = path.read_text()
        updated = re.sub(re.escape(OLD) + r'(?!/go(?:/|"))', NEW, text)
        updated = updated.replace('"' + NEW + '"', '"' + NEW + '/assets"')
        if path.name.endswith("_test.go"):
            updated = updated.replace('"../spec', '"../../spec')
        if text != updated:
            path.write_text(updated)
    mod = root / "go/go.mod"
    text = mod.read_text()
    mod.write_text(re.sub(r"(?m)^module " + re.escape(OLD) + r"$", "module " + NEW, text))
    package_pattern = "|".join(map(re.escape, sorted(packages)))
    for path in [root / "README.md", *sorted((root / "docs").glob("*.md"))]:
        text = path.read_text()
        updated = re.sub(r"(?<=\.\./)(?=(?:" + package_pattern + r")/)", "go/", text)
        updated = re.sub(r"`(?=(?:" + package_pattern + r")/)", "`go/", updated)
        updated = relocate_commands(updated).replace("go -C go build -o bin/", "go -C go build -o ../bin/")
        if text != updated:
            path.write_text(updated)
    for path in sorted((root / ".github/workflows").glob("*.y*ml")):
        text = path.read_text()
        updated = text.replace("go-version-file: go.mod", "go-version-file: go/go.mod")
        updated = relocate_commands(updated).replace("go -C go build -o bin/", "go -C go build -o ../bin/")
        if text != updated:
            path.write_text(updated)


def relocate_commands(text):
    return re.sub(r"(?<!-C )\bgo (build|vet|test|run) ", r"go -C go \1 ", text)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    relocate(parser.parse_args().root.resolve())
