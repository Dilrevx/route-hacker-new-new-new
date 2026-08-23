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


def workspace_dependency_projection(
    qlpack_path: Path,
    versions_by_name: dict[str, str],
) -> tuple[str, list[dict[str, str]]]:
    """Expand only `${workspace}` references into versions from the same tag."""

    source = qlpack_path.read_text(encoding="utf-8")
    replacements: list[dict[str, str]] = []

    def replace(match: re.Match[str]) -> str:
        indentation, name = match.groups()
        version = versions_by_name.get(name)
        if not version:
            raise RuntimeError(
                f"{qlpack_path} has a workspace dependency without a matching source pack: {name}"
            )
        replacements.append({"name": name, "version": version})
        return f"{indentation}{name}: {version}"

    rendered = re.sub(
        r"(?m)^(\s+)(codeql/[A-Za-z0-9_-]+):\s*\$\{workspace\}\s*$",
        replace,
        source,
    )
    return rendered, replacements


def pack_dependencies(
    qlpack_path: Path,
    versions_by_name: dict[str, str],
) -> list[str]:
    source = qlpack_path.read_text(encoding="utf-8")
    dependencies: list[str] = []
    for match in re.finditer(r"(?m)^\s+(codeql/[A-Za-z0-9_-]+):\s*([^\s#]+)", source):
        name, version = match.groups()
        if version == "${workspace}" and name not in versions_by_name:
            raise RuntimeError(
                f"{qlpack_path} has a workspace dependency without a matching source pack: {name}"
            )
        dependencies.append(name)
    return dependencies


def required_pack_closure(packs: list[dict[str, str]]) -> list[dict[str, str]]:
    by_name: dict[str, dict[str, str]] = {}
    for pack in packs:
        name = str(pack["name"])
        version = str(pack["version"])
        prior = by_name.get(name)
        if prior is None or version > str(prior["version"]):
            by_name[name] = pack
    pending = ["codeql/java-queries"]
    selected: set[str] = set()
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        pack = by_name.get(name)
        if not pack:
            raise RuntimeError(f"required source dependency is absent: {name}")
        selected.add(name)
        pending.extend(pack_dependencies(Path(pack["source"]) / "qlpack.yml", {
            key: str(value["version"]) for key, value in by_name.items()
        }))
    return [by_name[name] for name in sorted(selected)]


def project_pack(
    pack: dict[str, str],
    versions_by_name: dict[str, str],
    output_root: Path,
) -> dict[str, object]:
    source = Path(pack["source"])
    destination = output_root / "qlpacks" / Path(pack["name"]) / pack["version"]
    shutil.copytree(source, destination, symlinks=True)
    qlpack = destination / "qlpack.yml"
    rendered, replacements = workspace_dependency_projection(
        source / "qlpack.yml",
        versions_by_name,
    )
    qlpack.write_text(rendered, encoding="utf-8")
    return {
        **pack,
        "projected_path": str(destination),
        "source_qlpack_sha256": sha256_path(source / "qlpack.yml"),
        "projected_qlpack_sha256": sha256_path(qlpack),
        "workspace_dependency_replacements": replacements,
    }


def build_overlay(codeql_dir: Path, source_root: Path, output_dir: Path) -> dict[str, object]:
    cli_version = codeql_cli_version(codeql_dir)
    source_provenance = validate_official_source_tag(source_root, cli_version)
    packs = required_pack_closure(discover_codeql_packs(source_root))
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
    (output_dir / "codeql").symlink_to(codeql_dir / "codeql")
    versions_by_name = {str(pack["name"]): str(pack["version"]) for pack in packs}
    projected_packs = [
        project_pack(pack, versions_by_name, output_dir)
        for pack in packs
    ]
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
        "packs": projected_packs,
        "contract": {
            "official_source_tag_matches_cli_version": True,
            "query_files_copied_verbatim_from_official_source_tag": True,
            "only_qlpack_workspace_dependencies_are_rendered": True,
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
