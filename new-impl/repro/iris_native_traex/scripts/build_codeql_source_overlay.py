#!/usr/bin/env python3
"""Build a read-only CodeQL pack overlay from an official matching source tag."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def qlpack_value(path: Path, key: str) -> str | None:
    match = re.search(
        rf"^\s*{re.escape(key)}:\s*([^\s#]+)",
        path.read_text(encoding="utf-8"),
        flags=re.MULTILINE,
    )
    return match.group(1) if match else None


def codeql_cli_version(codeql_dir: Path) -> str:
    executable = codeql_dir / "codeql"
    if not executable.is_file():
        raise FileNotFoundError(f"missing CodeQL executable: {executable}")
    completed = subprocess.run(
        [str(executable), "version"],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"CodeQL version probe failed ({completed.returncode}): "
            f"{completed.stderr.strip()[-500:]}"
        )
    match = re.search(r"release\s+([0-9]+(?:\.[0-9]+){1,2})", completed.stdout)
    if not match:
        raise RuntimeError(f"cannot parse CodeQL release from: {completed.stdout!r}")
    return match.group(1)


def git_output(source_root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(source_root), *args],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed ({completed.returncode}): "
            f"{completed.stderr.strip()[-500:]}"
        )
    return completed.stdout.strip()


def validate_official_source_tag(source_root: Path, cli_version: str) -> dict[str, str]:
    if not (source_root / ".git").exists():
        raise RuntimeError(f"CodeQL source root must be a Git checkout: {source_root}")
    if git_output(source_root, "status", "--porcelain"):
        raise RuntimeError(f"CodeQL source root has uncommitted tracked changes: {source_root}")
    source_commit = git_output(source_root, "rev-parse", "HEAD")
    tag = f"codeql-cli/v{cli_version}"
    tag_commit = git_output(source_root, "rev-parse", "--verify", f"{tag}^{{commit}}")
    if source_commit != tag_commit:
        raise RuntimeError(
            "CodeQL source checkout does not match the installed CLI release tag: "
            f"HEAD={source_commit}, {tag}={tag_commit}"
        )
    return {"tag": tag, "commit": source_commit}


def discover_codeql_packs(source_root: Path) -> list[dict[str, str]]:
    packs: dict[tuple[str, str], Path] = {}
    for qlpack in sorted(source_root.rglob("qlpack.yml")):
        name = qlpack_value(qlpack, "name")
        version = qlpack_value(qlpack, "version")
        if not name or not version or not name.startswith("codeql/"):
            continue
        key = (name, version)
        existing = packs.get(key)
        if existing and existing != qlpack.parent:
            raise RuntimeError(
                f"ambiguous source pack {name}@{version}: {existing} and {qlpack.parent}"
            )
        packs[key] = qlpack.parent
    if not packs:
        raise RuntimeError(f"no versioned codeql/* packs found beneath {source_root}")
    return [
        {"name": name, "version": version, "source": str(path)}
        for (name, version), path in sorted(packs.items())
    ]


def symlink_exact(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.symlink_to(source, target_is_directory=True)


def build_overlay(codeql_dir: Path, source_root: Path, output_dir: Path) -> dict[str, object]:
    cli_version = codeql_cli_version(codeql_dir)
    source_provenance = validate_official_source_tag(source_root, cli_version)
    packs = discover_codeql_packs(source_root)
    required = {
        "codeql/java-queries": False,
        "codeql/java-all": False,
        "codeql/util": False,
        "codeql/suite-helpers": False,
    }
    for pack in packs:
        if pack["name"] in required:
            required[pack["name"]] = True
    missing = [name for name, present in required.items() if not present]
    if missing:
        raise RuntimeError(
            "official CodeQL source tag is missing required IRIS dependency packs: "
            + ", ".join(missing)
        )
    if output_dir.exists():
        raise RuntimeError(f"refusing to replace existing overlay: {output_dir}")
    output_dir.mkdir(parents=True)
    symlink_exact(codeql_dir / "codeql", output_dir / "codeql")
    for pack in packs:
        name_path = Path(pack["name"])
        symlink_exact(Path(pack["source"]), output_dir / "qlpacks" / name_path / pack["version"])
    manifest = {
        "schema_version": "iris_codeql_source_overlay.v1",
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "kind": "github_codeql_source_tag_overlay",
        "codeql_cli": {
            "version": cli_version,
            "source": str(codeql_dir / "codeql"),
            "sha256": sha256_path(codeql_dir / "codeql"),
        },
        "source_tag": source_provenance,
        "source_root": str(source_root),
        "packs": packs,
        "contract": {
            "official_source_tag_matches_cli_version": True,
            "no_query_files_copied_or_modified": True,
            "overlay_contains_symlinks_only": True,
            "not_an_action_bundle": True,
        },
    }
    (output_dir / ".iris_codeql_source_overlay.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codeql-dir", type=Path, required=True)
    parser.add_argument("--codeql-source-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    manifest = build_overlay(
        args.codeql_dir.resolve(),
        args.codeql_source_root.resolve(),
        args.output_dir.resolve(),
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
