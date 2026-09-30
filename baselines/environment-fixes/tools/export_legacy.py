#!/usr/bin/env python3
"""Export an allowlisted historical catalog and exact recipe bytes; never run them."""

import argparse
import collections
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sqlite3
import tarfile


EXPECTED_DB = "50be076b17adcbbb61445b6d021f68f8a79849eeb9271aed7210223604c72579"
EXPECTED_BUNDLE = "5163e9c4c8b18f73d8d4180343f8580d8c220a7abb0ffd05b12ff9dac240fa02"
FIELDS = (
    "id", "repo_slug", "revision", "jdk_version", "runtime_type",
    "build_status", "artifact_category", "is_verified", "can_build",
    "build_duration_seconds", "created_at",
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def checked_input(path, expected):
    data = path.read_bytes()
    if sha256(data) != expected:
        raise ValueError(f"Input hash mismatch: {path.name}")
    return data


def safe_member(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or len(path.parts) not in (2, 3):
        raise ValueError(f"Unsafe or unexpected member: {name}")
    if path.name not in ("Dockerfile", "build-notes.md"):
        raise ValueError(f"Unexpected file type: {name}")
    return path


def identifier_kind(value):
    if value is None:
        return "unspecified"
    if value.isdigit():
        return "numeric_token_not_resolved_to_commit"
    if re.fullmatch(r"[0-9a-f]{40}", value):
        return "full_hex_revision_not_freshly_checked_out"
    if re.fullmatch(r"[0-9a-f]{7,39}", value):
        return "abbreviated_hex_revision_not_freshly_checked_out"
    return "other_historical_identifier"


def dump(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def export(source, dest):
    db = source / "runtime-catalog.snapshot.sqlite"
    bundle = source / "dockerfiles-backup-20260704-150750.tar.gz"
    checked_input(db, EXPECTED_DB)
    checked_input(bundle, EXPECTED_BUNDLE)
    if dest.exists():
        raise FileExistsError("Choose a fresh output directory; no overwrite is allowed")
    # This consistent serialized snapshot retains a WAL-mode header. It is
    # immutable and contains all pages, so no adjacent WAL or SHM is required.
    with sqlite3.connect(db.resolve().as_uri() + "?mode=ro&immutable=1", uri=True) as con:
        con.row_factory = sqlite3.Row
        if con.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("Invalid catalog snapshot")
        rows = [dict(row) for row in con.execute(
            "SELECT " + ",".join(FIELDS) + " FROM runtime_configs ORDER BY id"
        )]
    # Never export env_vars_json, image registry, logs, notes, live instances,
    # failure messages, or job metadata from the private database.
    by_key = collections.defaultdict(list)
    for row in rows:
        by_key[(row["repo_slug"].casefold(), row["revision"])].append(row["id"])
    members = []
    seen = set()
    with tarfile.open(bundle, "r:gz") as archive:
        for member in archive:
            if member.isdir():
                continue
            relative = safe_member(member.name)
            if not member.isfile() or relative in seen or member.size > 1_000_000:
                raise ValueError(f"Unexpected archive member: {member.name}")
            seen.add(relative)
            data = archive.extractfile(member).read()
            data.decode("utf-8")
            members.append((relative, data))
    dest.mkdir(parents=True)
    files = []
    recipes = {}
    for relative, data in sorted(members):
        target = dest / "recipes" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        files.append({"path": str(target.relative_to(dest)), "bytes": len(data),
                      "sha256": sha256(data), "source_member": "./" + str(relative)})
        if relative.name != "Dockerfile":
            continue
        parts = relative.parts
        repo = parts[0]
        revision = parts[1] if len(parts) == 3 else None
        content = data.decode()
        recipes[str(relative.parent)] = {
            "recipe": str(target.relative_to(dest)),
            "repo_slug": repo,
            "historical_identifier": revision,
            "identifier_kind": identifier_kind(revision),
            "catalog_id_candidates": by_key.get((repo.casefold(), revision), []),
            "catalog_join": "casefolded_repo_and_literal_revision_only_not_execution_proof",
            "from_images": re.findall(r"^FROM\s+(\S+)", content, re.MULTILINE),
            "build_context_instructions": re.findall(r"^(?:COPY|ADD)\s+(.+)", content, re.MULTILINE),
            "status": "historical_recipe_not_rebuilt_during_preservation",
        }
    counts = lambda key: dict(sorted(collections.Counter(str(r[key]) for r in rows).items()))
    dump(dest / "catalog.json", {
        "schema_version": 1,
        "source_sha256": EXPECTED_DB,
        "evidence_level": "historical_catalog_flags_not_independent_current_verification",
        "records": rows,
    })
    dump(dest / "recipe-index.json", {
        "schema_version": 1,
        "source_bundle_sha256": EXPECTED_BUNDLE,
        "recipes": list(recipes.values()),
    })
    dump(dest / "source-manifest.json", {
        "schema_version": 1,
        "preserved_on": "2026-09-30",
        "source_bundle": "dockerfiles-backup-20260704-150750.tar.gz",
        "source_bundle_sha256": EXPECTED_BUNDLE,
        "files_are_original_bytes": True,
        "files": files,
        "summary": {
            "catalog_records": len(rows), "recipe_files": len(files),
            "dockerfiles": len(recipes),
            "build_notes": len(files) - len(recipes),
            "recipe_folders_with_literal_catalog_match": sum(bool(r["catalog_id_candidates"]) for r in recipes.values()),
            "catalog_build_status": counts("build_status"),
            "catalog_is_verified": counts("is_verified"),
            "catalog_can_build": counts("can_build"),
        },
    })
    return len(files)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(f"Exported {export(args.source, args.output)} historical recipe files; none executed.")
