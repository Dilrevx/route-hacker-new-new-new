"""Constrained, auditable CodeQL build repair primitives.

The benchmark repair lane is deliberately separate from retrieval.  It accepts
only a failed exact-revision CodeQL receipt, lets a deterministic policy or an
LLM select from a small allow-list of environment/build adjustments, and
independently verifies the source revision and resulting database.

The module never edits benchmark source, substitutes a revision, changes an
official query, or accepts a pre-existing database as a repaired result.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from route_hacker.runtime.bounded_process import run_bounded_process


SCHEMA_VERSION = "route_hacker_codeql_repair.v1"
MAX_LOG_CHARACTERS = 12_000
MAX_RATIONALE_CHARACTERS = 1_000
MAX_ACTIONS = 4
SAFE_BUILD_ARGS = frozenset(
    {
        "-Dmaven.buildNumber.skip=true",
        "-Dcheckstyle.skip=true",
        "-Denforcer.skip=true",
        "-Dfindbugs.skip=true",
        "-Dlicense.skip=true",
        "-Dmaven.gitcommitid.skip=true",
        "-Dmaven.javadoc.skip=true",
        "-Dmaven.source.skip=true",
        "-Dmaven.test.skip=true",
        "-Dpmd.skip=true",
        "-Drat.skip=true",
        "-DskipITs",
        "-DskipTests",
        "-Dspotbugs.skip=true",
        "-Dspotless.apply.skip=true",
        "-Dspotless.check.skip=true",
        "-Dspotless.skip=true",
    }
)
SAFE_MAVEN_HEAP_OPTIONS = frozenset({"-Xmx2g", "-Xmx4g", "-Xmx6g"})
MAVEN_LIFECYCLE_GOALS = frozenset(
    {
        "validate",
        "initialize",
        "generate-sources",
        "process-sources",
        "generate-resources",
        "process-resources",
        "compile",
        "process-classes",
        "generate-test-sources",
        "process-test-sources",
        "generate-test-resources",
        "process-test-resources",
        "test-compile",
        "process-test-classes",
        "test",
        "prepare-package",
        "package",
        "pre-integration-test",
        "integration-test",
        "post-integration-test",
        "verify",
        "install",
        "deploy",
    }
)
SECRET_PATTERN = re.compile(
    r"(?im)(api[_-]?key|authorization|bearer|password|secret|token)"
    r"(\s*[:=]\s*|\s+)([^\r\n]+)"
)


class RepairValidationError(ValueError):
    """Raised when a proposal crosses the constrained repair boundary."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stable_json_sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def redact_text(value: str) -> str:
    """Remove obvious credentials before a build log is placed in an LLM packet."""

    return SECRET_PATTERN.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", value)


def read_log_excerpt(path: Path | None, limit: int = MAX_LOG_CHARACTERS) -> dict[str, Any]:
    if path is None:
        return {"path": None, "sha256": None, "excerpt": "", "available": False}
    if not path.is_file():
        return {"path": str(path), "sha256": None, "excerpt": "", "available": False}
    text = path.read_text(encoding="utf-8", errors="replace")
    return {
        "path": str(path),
        "sha256": sha256_file(path),
        "excerpt": redact_text(text[-limit:]),
        "available": True,
    }


def classify_build_failure(log_text: str) -> str:
    """Classify a failed build into a small, repair-relevant taxonomy."""

    patterns: tuple[tuple[str, str], ...] = (
        (
            "java_toolchain",
            r"JCTree\$JCImport[\s\S]*qualid[\s\S]*lombok|"
            r"lombok\.javac\.[\s\S]*JCTree\$JCImport[\s\S]*qualid",
        ),
        (
            "maven_buildnumber_scm_metadata_unavailable",
            r"buildnumber-maven-plugin:.*:(?:create|create-metadata).*"
            r"(?:NullPointerException|failed|Cannot get the revision information|"
            r"not a git repository)|"
            r"Cannot get the branch information from the git repository.*"
            r"not a git repository|"
            r"Cannot get the revision information from the scm repository",
        ),
        (
            "maven_git_metadata_unavailable",
            r"git-commit-id-maven-plugin.*\.git directory is not found|"
            r"\.git directory is not found.*git-commit-id-maven-plugin",
        ),
        (
            "gradle_scm_metadata_unavailable",
            r"Failed to apply plugin [^\r\n]*(?:build|git)[^\r\n]*"
            r"(?:\r?\n[^\r\n]*){0,4}"
            r"Process 'command 'git'' finished with non-zero exit value 128|"
            r"git rev-parse --verify HEAD.*(?:exit value 128|not a git repository)",
        ),
        (
            "maven_enforcer_api_incompatibility",
            r"maven-enforcer-plugin.*(?:NoSuchMethodError|API incompatibility)|"
            r"enforce-best-practices.*NoSuchMethodError",
        ),
        (
            "maven_reactor_artifact_phase",
            r"Could not find artifact .*:(?:tests|test-jar):.*(?:absent|not found)|"
            r"Could not resolve dependencies.*(?:tests|test-jar):.*(?:absent|not found)",
        ),
        (
            "maven_reactor_plugin_descriptor_phase",
            r"Failed to parse plugin descriptor for .*?/target/classes.*"
            r"No plugin descriptor found at META-INF/maven/plugin\.xml",
        ),
        (
            "maven_reactor_package_phase",
            r"Artifact has not been packaged yet(?:; it is part of the reactor, "
            r"but the package phase has not been executed|\. When used on "
            r"reactor artifact, .* should be executed after packaging)",
        ),
        (
            "maven_quality_gate",
            r"(?:spotless-maven-plugin|maven-checkstyle-plugin|"
            r"apache-rat-plugin|maven-pmd-plugin|spotbugs-maven-plugin).*"
            r"(?:format violations|check|rat check|violations|"
            r"Cannot find git repository|Security Manager is deprecated)",
        ),
        (
            "maven_toolchain",
            r"requires Maven version|"
            r"Detected Maven Version: .*allowed range|"
            r"plugin .* requires Maven version",
        ),
        (
            "maven_corrupted_artifact",
            r"The JAR/ZIP file .* seems corrupted|"
            r"error in opening zip file|"
            r"zip file is empty|"
            r"invalid LOC header",
        ),
        (
            "dependency_or_network",
            r"Could not (?:resolve|transfer)|Non-resolvable|PKIX|"
            r"Connection (?:reset|timed out)|Read timed out|Unknown host",
        ),
        (
            "java_toolchain",
            r"Unsupported class file|release version|source release|target release|"
            r"requires Java|requires JDK|invalid target release|"
            r"invalid flag:\s*--release|class file has wrong version|"
            r"Detected JDK version .* is not in the allowed range|"
            r"JCTree\$JCImport[\s\S]*qualid[\s\S]*lombok|"
            r"lombok\.javac\.[\s\S]*JCTree\$JCImport[\s\S]*qualid",
        ),
        (
            "ant_toolchain",
            r"Runner failed to start 'ant': No such file or directory|"
            r"\bant:\s*(?:command )?not found\b|"
            r"\bant\b.*(?:No such file or directory|not found)",
        ),
        (
            "gradle_wrapper_or_path",
            r"Permission denied|No such file|not found|gradlew|Gradle .*not found",
        ),
        (
            "codeql_no_source_capture",
            r"CodeQL detected code written in Java/Kotlin but could not process any of it|"
            r"no source code seen during build|"
            r"no Java/Kotlin source code was seen during the build",
        ),
        ("resource_exhaustion", r"OutOfMemory|Java heap space|GC overhead|Killed process"),
    )
    for category, pattern in patterns:
        if re.search(pattern, log_text, flags=re.IGNORECASE):
            return category
    if re.search(r"BUILD FAILURE|FAILURE: Build failed", log_text, flags=re.IGNORECASE):
        return "generic_build_failure"
    return "unclassified"


def source_revision_evidence(source_dir: Path, expected_revision: str) -> dict[str, Any]:
    """Verify that a repair uses the declared source checkout, never a fallback."""

    evidence: dict[str, Any] = {
        "source_dir": str(source_dir),
        "expected_revision": expected_revision,
        "git_head": None,
        "verified": False,
        "reason": None,
    }
    if not expected_revision:
        evidence["reason"] = "missing_expected_revision"
        return evidence
    if not source_dir.is_dir():
        evidence["reason"] = "source_directory_missing"
        return evidence
    try:
        completed = subprocess.run(
            ["git", "-C", str(source_dir), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        evidence["reason"] = f"git_revision_probe_error:{type(error).__name__}"
        return evidence
    if completed.returncode != 0:
        evidence["reason"] = "git_revision_probe_failed"
        return evidence
    head = completed.stdout.strip()
    evidence["git_head"] = head
    if head.startswith(expected_revision) or expected_revision.startswith(head):
        evidence["verified"] = True
        return evidence
    evidence["reason"] = "git_head_does_not_match_expected_revision"
    return evidence


def archive_snapshot_evidence(
    source_dir: Path,
    expected_revision: str,
    source_receipt: Mapping[str, Any] | None,
    expected_case_id: str | None,
) -> dict[str, Any]:
    """Validate a codeload-style exact snapshot when a Git worktree is absent."""

    evidence: dict[str, Any] = {
        "source_receipt_present": source_receipt is not None,
        "source_receipt_case_id": source_receipt.get("case_id") if source_receipt else None,
        "expected_case_id": expected_case_id,
        "source_dir_exists": source_dir.is_dir(),
        "case_id_matches_receipt": False,
        "source_receipt_status": source_receipt.get("status") if source_receipt else None,
        "source_dir_matches_receipt": False,
        "expected_revision_matches_receipt": False,
        "archive_url_matches_revision": False,
        "archive_sha256_verified": False,
        "verified": False,
        "reason": None,
    }
    if source_receipt is None:
        evidence["reason"] = "source_receipt_missing"
        return evidence
    if not evidence["source_dir_exists"]:
        evidence["reason"] = "source_directory_missing"
        return evidence
    evidence["case_id_matches_receipt"] = bool(
        expected_case_id
        and isinstance(source_receipt.get("case_id"), str)
        and source_receipt["case_id"] == expected_case_id
    )
    if not evidence["case_id_matches_receipt"]:
        evidence["reason"] = "source_receipt_case_id_mismatch"
        return evidence
    source_receipt_dir = source_receipt.get("source_dir")
    if not isinstance(source_receipt_dir, str) or not source_receipt_dir:
        evidence["reason"] = "source_receipt_source_dir_missing"
        return evidence
    try:
        evidence["source_dir_matches_receipt"] = source_dir.resolve() == Path(source_receipt_dir).resolve()
    except OSError:
        evidence["reason"] = "source_dir_resolution_failed"
        return evidence
    receipt_revision = str(
        source_receipt.get("resolved_buggy_commit")
        or source_receipt.get("declared_buggy_commit")
        or ""
    )
    evidence["expected_revision_matches_receipt"] = bool(
        expected_revision
        and receipt_revision
        and (
            receipt_revision.startswith(expected_revision)
            or expected_revision.startswith(receipt_revision)
        )
    )
    exact_statuses = {
        "source_materialized_exact_clean_snapshot",
        "source_reused_exact_clean_snapshot",
        "source_materialized_exact_archive_snapshot",
    }
    archive_result = source_receipt.get("archive_result")
    archive = archive_result if isinstance(archive_result, Mapping) else {}
    archive_url = str(archive.get("archive_url") or "")
    archive_path = archive.get("archive_path")
    expected_sha = archive.get("archive_sha256")
    evidence["archive_url_matches_revision"] = bool(
        archive_url and expected_revision and archive_url.rstrip("/").endswith(expected_revision)
    )
    if isinstance(archive_path, str) and isinstance(expected_sha, str) and Path(archive_path).is_file():
        evidence["archive_sha256_verified"] = sha256_file(Path(archive_path)) == expected_sha
    else:
        # An exact clean snapshot can be produced by a verified clone rather
        # than a retained archive. Its source receipt remains the audit root.
        evidence["archive_sha256_verified"] = (
            source_receipt.get("status") in {
                "source_materialized_exact_clean_snapshot",
                "source_reused_exact_clean_snapshot",
            }
        )
    allowed_contract = source_receipt.get("contract")
    contract = allowed_contract if isinstance(allowed_contract, Mapping) else {}
    policy_ok = contract.get("exact_declared_buggy_commit_only") is True
    evidence["verified"] = bool(
        source_receipt.get("status") in exact_statuses
        and evidence["source_dir_matches_receipt"]
        and evidence["expected_revision_matches_receipt"]
        and evidence["archive_sha256_verified"]
        and policy_ok
        and (
            evidence["archive_url_matches_revision"]
            or source_receipt.get("status")
            in {
                "source_materialized_exact_clean_snapshot",
                "source_reused_exact_clean_snapshot",
            }
        )
    )
    if not evidence["verified"]:
        evidence["reason"] = "source_archive_receipt_did_not_prove_exact_revision"
    return evidence


def verify_exact_source(
    source_dir: Path,
    expected_revision: str,
    source_receipt: Mapping[str, Any] | None,
    *,
    expected_case_id: str | None,
) -> dict[str, Any]:
    """Use Git proof when available, otherwise an exact snapshot receipt."""

    git_evidence = source_revision_evidence(source_dir, expected_revision)
    snapshot_evidence = archive_snapshot_evidence(
        source_dir,
        expected_revision,
        source_receipt,
        expected_case_id,
    )
    return {
        "verified": bool(git_evidence["verified"] or snapshot_evidence["verified"]),
        "verification_mode": (
            "git_checkout"
            if git_evidence["verified"]
            else "source_snapshot_receipt"
            if snapshot_evidence["verified"]
            else None
        ),
        "git_checkout": git_evidence,
        "source_snapshot_receipt": snapshot_evidence,
    }


def valid_codeql_database(path: Path) -> bool:
    """Require metadata and extracted Java relations, not merely a directory."""

    database_yml = path / "codeql-database.yml"
    java_default = path / "db-java" / "default"
    return database_yml.is_file() and java_default.is_dir() and any(java_default.glob("*.rel"))


def _required_receipt_field(receipt: Mapping[str, Any], name: str) -> str:
    value = receipt.get(name)
    if not isinstance(value, str) or not value:
        raise RepairValidationError(f"failed receipt is missing required field: {name}")
    return value


def _command_from_receipt(receipt: Mapping[str, Any]) -> list[str]:
    value = receipt.get("planned_codeql_database_command")
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise RepairValidationError("failed receipt has no usable planned_codeql_database_command")
    if len(value) < 4 or value[1:3] != ["database", "create"]:
        raise RepairValidationError("repair accepts only a CodeQL database create command")
    return list(value)


def _append_unique(values: list[str], additions: Iterable[str]) -> list[str]:
    for item in additions:
        if item not in values:
            values.append(item)
    return values


def is_maven_build_command(build_command: Sequence[str]) -> bool:
    """Return whether a parsed build command invokes Maven directly."""

    return bool(build_command) and Path(build_command[0]).name in {"mvn", "mvnw"}


def prepend_maven_clean_goal(build_command: Sequence[str]) -> list[str]:
    """Insert Maven's ``clean`` lifecycle before a supported build lifecycle.

    This action is deliberately narrower than arbitrary command rewriting:
    it only applies to a direct Maven invocation with an existing lifecycle
    goal. It deletes generated build outputs, never source files, and avoids
    treating arbitrary plugin invocations as an eligible clean rebuild.
    """

    rewritten = list(build_command)
    if not is_maven_build_command(rewritten):
        raise RepairValidationError("prepend_maven_clean requires a direct Maven build command")
    if "clean" in rewritten:
        return rewritten
    for index, token in enumerate(rewritten[1:], start=1):
        if token in MAVEN_LIFECYCLE_GOALS:
            rewritten.insert(index, "clean")
            return rewritten
    raise RepairValidationError(
        "prepend_maven_clean requires an existing Maven lifecycle build goal"
    )


def build_repair_packet(
    receipt: Mapping[str, Any],
    *,
    approved_java_homes: Sequence[str],
    approved_maven_homes: Sequence[str],
    approved_ant_homes: Sequence[str] = (),
    source_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Produce the sanitized, target-blind input to an LLM repair decision."""

    source_dir = _required_receipt_field(receipt, "source_dir")
    expected_revision = str(
        receipt.get("resolved_buggy_commit") or receipt.get("declared_buggy_commit") or ""
    )
    command = _command_from_receipt(receipt)
    build_command = shlex.split(_option_value(command, *_find_option(command, "--command"), "--command"))
    result = receipt.get("codeql_database_create_result")
    result_map = result if isinstance(result, Mapping) else {}
    log_path_text = result_map.get("log_path")
    log_path = Path(log_path_text) if isinstance(log_path_text, str) and log_path_text else None
    log = read_log_excerpt(log_path)
    category = classify_build_failure(str(log["excerpt"]))
    packet = {
        "schema_version": f"{SCHEMA_VERSION}:repair_packet",
        "case_id": receipt.get("case_id"),
        "project_slug": receipt.get("project_slug"),
        "source": {
            "source_dir": source_dir,
            "expected_revision": expected_revision,
            "source_receipt_sha256": receipt.get("input_source_receipt_sha256"),
            "snapshot_receipt": {
                "case_id": source_receipt.get("case_id") if source_receipt else None,
                "status": source_receipt.get("status") if source_receipt else None,
                "sha256": stable_json_sha256(source_receipt) if source_receipt else None,
            },
        },
        "failed_attempt": {
            "failure_kind": receipt.get("failure_kind"),
            "failure_category": category,
            "planned_codeql_database_command": command,
            "log": log,
        },
        "allowed_action_schema": {
            "maximum_actions": MAX_ACTIONS,
            "kinds": [
                "retry_same_command",
                "set_java_home",
                "set_maven_home",
                "set_ant_home",
                "append_build_args",
                "set_maven_heap",
                "prepend_maven_clean",
                "no_safe_action",
            ],
            "approved_java_homes": list(approved_java_homes),
            "approved_maven_homes": list(approved_maven_homes),
            "approved_ant_homes": list(approved_ant_homes),
            "safe_build_args": sorted(SAFE_BUILD_ARGS),
            "safe_maven_heap_options": sorted(SAFE_MAVEN_HEAP_OPTIONS),
            "allow_prepend_maven_clean": is_maven_build_command(build_command),
            "prohibited": [
                "source edits",
                "revision substitution",
                "query changes",
                "database reuse",
                "arbitrary shell commands",
                "network credential changes",
            ],
        },
    }
    packet["packet_sha256"] = stable_json_sha256(packet)
    return packet


def refresh_attempt_packet_log(
    packet: Mapping[str, Any],
    *,
    log_path: Path,
) -> dict[str, Any]:
    """Bind a completed attempt's packet to its final redacted build log."""

    refreshed = dict(packet)
    failed_attempt = packet.get("failed_attempt")
    if not isinstance(failed_attempt, Mapping):
        raise RepairValidationError("repair packet lacks failed attempt evidence")
    refreshed_failed_attempt = dict(failed_attempt)
    log = read_log_excerpt(log_path)
    refreshed_failed_attempt["log"] = log
    refreshed_failed_attempt["failure_category"] = classify_build_failure(
        str(log["excerpt"])
    )
    refreshed["failed_attempt"] = refreshed_failed_attempt
    refreshed["packet_sha256"] = stable_json_sha256(
        {
            key: value
            for key, value in refreshed.items()
            if key != "packet_sha256"
        }
    )
    return refreshed


def heuristic_repair_decision(
    packet: Mapping[str, Any],
    *,
    preferred_maven_home: str | None = None,
) -> dict[str, Any]:
    """Offer only conservative deterministic actions before using an LLM."""

    category = (
        packet.get("failed_attempt", {}).get("failure_category")
        if isinstance(packet.get("failed_attempt"), Mapping)
        else None
    )
    if category == "maven_buildnumber_scm_metadata_unavailable":
        actions = [
            {
                "kind": "append_build_args",
                "args": ["-Dmaven.buildNumber.skip=true"],
            }
        ]
    elif category == "maven_git_metadata_unavailable":
        actions = [
            {
                "kind": "append_build_args",
                "args": ["-Dmaven.gitcommitid.skip=true"],
            }
        ]
    elif category == "gradle_scm_metadata_unavailable":
        actions = [{"kind": "no_safe_action"}]
    elif category == "maven_enforcer_api_incompatibility":
        actions = [{"kind": "append_build_args", "args": ["-Denforcer.skip=true"]}]
    elif category == "maven_quality_gate":
        actions = [
            {
                "kind": "append_build_args",
                "args": [
                    "-Dcheckstyle.skip=true",
                    "-Dlicense.skip=true",
                    "-Dpmd.skip=true",
                    "-Drat.skip=true",
                    "-Dspotbugs.skip=true",
                    "-Dspotless.apply.skip=true",
                    "-Dspotless.check.skip=true",
                    "-Dspotless.skip=true",
                ],
            }
        ]
    elif category == "maven_toolchain" and preferred_maven_home:
        actions = [{"kind": "set_maven_home", "maven_home": preferred_maven_home}]
    elif category == "resource_exhaustion":
        actions = [{"kind": "set_maven_heap", "value": "-Xmx4g"}]
    elif category == "dependency_or_network":
        actions = [{"kind": "retry_same_command"}]
    else:
        actions = [{"kind": "no_safe_action"}]
    return {
        "schema_version": f"{SCHEMA_VERSION}:repair_decision",
        "actions": actions,
        "rationale": f"deterministic policy for {category or 'unclassified'}",
    }


def parse_repair_decision_text(text: str) -> dict[str, Any]:
    """Decode strict JSON, tolerating a Markdown code fence from a chat model."""

    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.IGNORECASE)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError as error:
        raise RepairValidationError(f"LLM repair decision is not JSON: {error.msg}") from error
    if not isinstance(value, dict):
        raise RepairValidationError("LLM repair decision must be a JSON object")
    return value


def _approved_home_from_action(
    raw_action: Mapping[str, Any],
    *,
    field: str,
    approved_homes: set[str],
    action_kind: str,
    label: str,
) -> str:
    """Read a home selection without widening the approved local allow-list.

    The Claude JSON schema names action-specific fields, while compatible
    OpenAI bridges may return their common ``value`` field.  Both forms are
    canonicalized here only after an exact approved-home membership check.
    """

    explicit = raw_action.get(field)
    generic = raw_action.get("value")
    if explicit is not None and generic is not None and explicit != generic:
        raise RepairValidationError(
            f"{action_kind} has conflicting {field} and value selections"
        )
    selected = explicit if explicit is not None else generic
    if not isinstance(selected, str) or selected not in approved_homes:
        raise RepairValidationError(
            f"{action_kind} must select an approved {label} home"
        )
    return selected


def validate_repair_decision(
    decision: Mapping[str, Any],
    *,
    approved_java_homes: Sequence[str],
    approved_maven_homes: Sequence[str],
    approved_ant_homes: Sequence[str] = (),
) -> dict[str, Any]:
    """Validate an allow-listed repair proposal and canonicalize a redundant retry.

    ``retry_same_command`` is a standalone no-op action. Some structured-model
    responses nevertheless include it alongside a concrete environment action.
    Keep the concrete allow-listed action, record the discarded no-op, and
    never turn the model response into an arbitrary command.
    """

    raw_actions = decision.get("actions")
    if not isinstance(raw_actions, list) or not raw_actions:
        raise RepairValidationError("repair decision requires a nonempty actions list")
    if len(raw_actions) > MAX_ACTIONS:
        raise RepairValidationError(f"repair decision exceeds {MAX_ACTIONS} actions")

    approved_java = set(approved_java_homes)
    approved_maven = set(approved_maven_homes)
    approved_ant = set(approved_ant_homes)
    actions: list[dict[str, Any]] = []
    seen_kinds: set[str] = set()
    for raw_action in raw_actions:
        if not isinstance(raw_action, Mapping):
            raise RepairValidationError("repair action must be an object")
        kind = raw_action.get("kind")
        if not isinstance(kind, str):
            raise RepairValidationError("repair action is missing kind")
        if kind in seen_kinds and kind != "append_build_args":
            raise RepairValidationError(f"duplicate repair action: {kind}")
        seen_kinds.add(kind)
        if kind == "retry_same_command":
            actions.append({"kind": kind})
        elif kind == "set_java_home":
            java_home = _approved_home_from_action(
                raw_action,
                field="java_home",
                approved_homes=approved_java,
                action_kind=kind,
                label="Java",
            )
            actions.append({"kind": kind, "java_home": java_home})
        elif kind == "set_maven_home":
            maven_home = _approved_home_from_action(
                raw_action,
                field="maven_home",
                approved_homes=approved_maven,
                action_kind=kind,
                label="Maven",
            )
            actions.append({"kind": kind, "maven_home": maven_home})
        elif kind == "set_ant_home":
            ant_home = _approved_home_from_action(
                raw_action,
                field="ant_home",
                approved_homes=approved_ant,
                action_kind=kind,
                label="Ant",
            )
            actions.append({"kind": kind, "ant_home": ant_home})
        elif kind == "append_build_args":
            args = raw_action.get("args")
            if args is None:
                value = raw_action.get("value")
                args = [value] if isinstance(value, str) else None
            if not isinstance(args, list) or not args or not all(isinstance(arg, str) for arg in args):
                raise RepairValidationError("append_build_args requires a nonempty string args list")
            if not set(args).issubset(SAFE_BUILD_ARGS):
                raise RepairValidationError("append_build_args contains an unapproved argument")
            existing = next(
                (action for action in actions if action["kind"] == kind),
                None,
            )
            if existing is None:
                actions.append({"kind": kind, "args": list(args)})
            else:
                existing["args"] = _append_unique(existing["args"], args)
        elif kind == "set_maven_heap":
            value = raw_action.get("value")
            if not isinstance(value, str) or value not in SAFE_MAVEN_HEAP_OPTIONS:
                raise RepairValidationError("set_maven_heap requires an approved heap option")
            actions.append({"kind": kind, "value": value})
        elif kind == "prepend_maven_clean":
            actions.append({"kind": kind})
        elif kind == "no_safe_action":
            actions.append({"kind": kind})
        else:
            raise RepairValidationError(f"unsupported repair action: {kind}")

    if "no_safe_action" in seen_kinds and len(actions) != 1:
        raise RepairValidationError("no_safe_action cannot be combined with an execution action")
    normalization: dict[str, Any] = {"dropped_redundant_actions": []}
    if "retry_same_command" in seen_kinds and len(actions) != 1:
        actions = [action for action in actions if action["kind"] != "retry_same_command"]
        normalization["dropped_redundant_actions"] = ["retry_same_command"]

    rationale = decision.get("rationale", "")
    if not isinstance(rationale, str):
        raise RepairValidationError("repair rationale must be text")
    sanitized_rationale = redact_text(rationale[:MAX_RATIONALE_CHARACTERS])
    return {
        "schema_version": f"{SCHEMA_VERSION}:validated_repair_decision",
        "actions": actions,
        "normalization": normalization,
        "rationale": sanitized_rationale,
        "decision_sha256": stable_json_sha256(
            {
                "actions": actions,
                "normalization": normalization,
                "rationale": sanitized_rationale,
            }
        ),
    }


def _find_option(command: list[str], flag: str) -> tuple[int, bool]:
    """Return an option index and whether its value is stored inline."""

    for index, value in enumerate(command):
        if value == flag:
            return index, False
        if value.startswith(f"{flag}="):
            return index, True
    raise RepairValidationError(f"CodeQL command is missing {flag}")


def _option_value(command: list[str], index: int, inline: bool, flag: str) -> str:
    if inline:
        value = command[index].removeprefix(f"{flag}=")
    elif index + 1 < len(command):
        value = command[index + 1]
    else:
        value = ""
    if not value:
        raise RepairValidationError(f"CodeQL option {flag} has no value")
    return value


def apply_repair_decision(
    command: Sequence[str],
    decision: Mapping[str, Any],
    *,
    attempt_database_dir: Path,
    approved_java_homes: Sequence[str],
    approved_maven_homes: Sequence[str],
    approved_ant_homes: Sequence[str] = (),
    verified_gradle_user_home: Path | None = None,
    isolated_build_home: Path | None = None,
) -> tuple[list[str], dict[str, str], dict[str, Any]]:
    """Turn a validated decision into a new isolated CodeQL command and env."""

    repaired = list(command)
    if len(repaired) < 4 or repaired[1:3] != ["database", "create"]:
        raise RepairValidationError("repair command must be CodeQL database create")
    repaired[3] = str(attempt_database_dir)
    source_index, source_inline = _find_option(repaired, "--source-root")
    source_root = _option_value(repaired, source_index, source_inline, "--source-root")
    build_index, build_inline = _find_option(repaired, "--command")
    build_value = _option_value(repaired, build_index, build_inline, "--command")
    build_command = shlex.split(build_value)
    if not build_command:
        raise RepairValidationError("CodeQL build command is empty")

    java_homes = set(approved_java_homes)
    maven_homes = set(approved_maven_homes)
    ant_homes = set(approved_ant_homes)
    env: dict[str, str] = {}
    actions = decision.get("actions")
    if not isinstance(actions, list):
        raise RepairValidationError("validated repair decision has no actions")
    applied_actions: list[dict[str, Any]] = []
    for action in actions:
        if not isinstance(action, Mapping):
            raise RepairValidationError("validated action is not an object")
        kind = action.get("kind")
        if kind == "no_safe_action":
            raise RepairValidationError("no_safe_action cannot be executed")
        if kind == "retry_same_command":
            applied_actions.append({"kind": kind})
        elif kind == "set_java_home":
            java_home = action.get("java_home")
            if not isinstance(java_home, str) or java_home not in java_homes:
                raise RepairValidationError("unapproved Java home in validated decision")
            env["JAVA_HOME"] = java_home
            env["PATH"] = f"{Path(java_home) / 'bin'}:{os.environ.get('PATH', '')}"
            applied_actions.append({"kind": kind, "java_home": java_home})
        elif kind == "set_maven_home":
            maven_home = action.get("maven_home")
            if not isinstance(maven_home, str) or maven_home not in maven_homes:
                raise RepairValidationError("unapproved Maven home in validated decision")
            maven_binary = Path(maven_home) / "bin" / "mvn"
            if not maven_binary.is_file() or not os.access(maven_binary, os.X_OK):
                raise RepairValidationError("approved Maven home has no executable mvn binary")
            env["PATH"] = f"{Path(maven_home) / 'bin'}:{env.get('PATH', os.environ.get('PATH', ''))}"
            env["MAVEN_HOME"] = maven_home
            env["M2_HOME"] = maven_home
            rewritten_executable = None
            # CodeQL can run its build command through a separate child shell.
            # An absolute, already-approved Maven binary removes PATH inheritance
            # ambiguity without changing the build arguments or source tree.
            if build_command[0] == "mvn":
                build_command[0] = str(maven_binary)
                rewritten_executable = str(maven_binary)
            applied_actions.append(
                {
                    "kind": kind,
                    "maven_home": maven_home,
                    "maven_binary": str(maven_binary),
                    "rewritten_build_executable": rewritten_executable,
                }
            )
        elif kind == "set_ant_home":
            ant_home = action.get("ant_home")
            if not isinstance(ant_home, str) or ant_home not in ant_homes:
                raise RepairValidationError("unapproved Ant home in validated decision")
            env["ANT_HOME"] = ant_home
            env["PATH"] = f"{Path(ant_home) / 'bin'}:{env.get('PATH', os.environ.get('PATH', ''))}"
            applied_actions.append({"kind": kind, "ant_home": ant_home})
        elif kind == "append_build_args":
            args = action.get("args")
            if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
                raise RepairValidationError("validated append_build_args is malformed")
            _append_unique(build_command, args)
            applied_actions.append({"kind": kind, "args": list(args)})
        elif kind == "set_maven_heap":
            heap = action.get("value")
            if not isinstance(heap, str) or heap not in SAFE_MAVEN_HEAP_OPTIONS:
                raise RepairValidationError("validated Maven heap action is malformed")
            existing = os.environ.get("MAVEN_OPTS", "")
            env["MAVEN_OPTS"] = f"{existing} {heap}".strip()
            applied_actions.append({"kind": kind, "value": heap})
        elif kind == "prepend_maven_clean":
            build_command = prepend_maven_clean_goal(build_command)
            applied_actions.append(
                {
                    "kind": kind,
                    "effect": "maven_clean_lifecycle_before_existing_build_goal",
                }
            )
        else:
            raise RepairValidationError(f"unexpected validated repair action: {kind}")

    repaired_build_value = shlex.join(build_command)
    if build_inline:
        repaired[build_index] = f"--command={repaired_build_value}"
    else:
        repaired[build_index + 1] = repaired_build_value
    verified_environment: dict[str, str] = {}
    if verified_gradle_user_home is not None:
        gradle_user_home = verified_gradle_user_home.resolve()
        if not gradle_user_home.is_dir():
            raise RepairValidationError("verified Gradle user home is not a directory")
        env["GRADLE_USER_HOME"] = str(gradle_user_home)
        verified_environment["GRADLE_USER_HOME"] = str(gradle_user_home)
    if isolated_build_home is not None:
        build_home = isolated_build_home.resolve()
        maven_user_home = build_home / ".m2"
        gradle_user_home = build_home / ".gradle"
        if (
            not build_home.is_dir()
            or not maven_user_home.is_dir()
            or not gradle_user_home.is_dir()
        ):
            raise RepairValidationError("isolated build home is incomplete")
        existing_maven_opts = os.environ.get("MAVEN_OPTS", "")
        user_home_option = f"-Duser.home={build_home}"
        env["HOME"] = str(build_home)
        env["MAVEN_USER_HOME"] = str(maven_user_home)
        env["GRADLE_USER_HOME"] = str(gradle_user_home)
        env["MAVEN_OPTS"] = (
            f"{existing_maven_opts} {user_home_option}".strip()
            if user_home_option not in existing_maven_opts
            else existing_maven_opts
        )
        verified_environment.update(
            {
                "HOME": str(build_home),
                "MAVEN_USER_HOME": str(maven_user_home),
                "GRADLE_USER_HOME": str(gradle_user_home),
                "MAVEN_OPTS_user_home": user_home_option,
            }
        )
    if "JAVA_HOME" in env:
        verified_environment["JAVA_HOME"] = env["JAVA_HOME"]
        verified_environment["PATH_prefix"] = str(Path(env["JAVA_HOME"]) / "bin")
    return repaired, env, {
        "applied_actions": applied_actions,
        "source_root": source_root,
        "attempt_database_dir": str(attempt_database_dir),
        "build_command": build_command,
        "verified_environment": verified_environment,
    }


def execute_repair_attempt(
    receipt: Mapping[str, Any],
    decision: Mapping[str, Any],
    *,
    attempt_dir: Path,
    timeout_seconds: float,
    approved_java_homes: Sequence[str],
    approved_maven_homes: Sequence[str],
    approved_ant_homes: Sequence[str] = (),
    source_receipt: Mapping[str, Any] | None = None,
    verified_gradle_user_home_source: Path | None = None,
    verified_maven_repository_source: Path | None = None,
    verified_maven_wrapper_dists_source: Path | None = None,
    isolate_build_home: bool = False,
) -> dict[str, Any]:
    """Execute one verified, isolated repair attempt and return an auditable receipt."""

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    attempt_dir.mkdir(parents=True, exist_ok=False)
    packet = build_repair_packet(
        receipt,
        approved_java_homes=approved_java_homes,
        approved_maven_homes=approved_maven_homes,
        approved_ant_homes=approved_ant_homes,
        source_receipt=source_receipt,
    )
    validated = validate_repair_decision(
        decision,
        approved_java_homes=approved_java_homes,
        approved_maven_homes=approved_maven_homes,
        approved_ant_homes=approved_ant_homes,
    )
    source_dir = Path(packet["source"]["source_dir"])
    expected_revision = str(packet["source"]["expected_revision"])
    source_evidence = verify_exact_source(
        source_dir,
        expected_revision,
        source_receipt,
        expected_case_id=receipt.get("case_id") if isinstance(receipt.get("case_id"), str) else None,
    )
    if not source_evidence["verified"]:
        return {
            "schema_version": f"{SCHEMA_VERSION}:attempt",
            "recorded_at": utc_now(),
            "case_id": receipt.get("case_id"),
            "project_slug": receipt.get("project_slug"),
            "status": "source_revision_verification_failed",
            "packet": packet,
            "validated_decision": validated,
            "source_revision_evidence": source_evidence,
        }

    original_command = _command_from_receipt(receipt)
    database_dir = attempt_dir / "codeql-db"
    source_gradle_user_home: Path | None = None
    if verified_gradle_user_home_source is not None:
        source_gradle_user_home = verified_gradle_user_home_source.resolve()
        if not source_gradle_user_home.is_dir():
            raise RepairValidationError("verified Gradle user home source is not a directory")
    source_maven_repository: Path | None = None
    if verified_maven_repository_source is not None:
        source_maven_repository = verified_maven_repository_source.resolve()
        if not source_maven_repository.is_dir():
            raise RepairValidationError(
                "verified Maven repository source is not a directory"
            )
        if not isolate_build_home:
            raise RepairValidationError(
                "verified Maven repository requires an isolated build home"
            )
    source_maven_wrapper_dists: Path | None = None
    if verified_maven_wrapper_dists_source is not None:
        source_maven_wrapper_dists = verified_maven_wrapper_dists_source.resolve()
        if not source_maven_wrapper_dists.is_dir():
            raise RepairValidationError(
                "verified Maven wrapper dists source is not a directory"
            )
        if not isolate_build_home:
            raise RepairValidationError(
                "verified Maven wrapper dists requires an isolated build home"
            )
    attempt_build_home: Path | None = None
    attempt_gradle_user_home: Path | None = None
    if isolate_build_home:
        attempt_build_home = attempt_dir / "build-home"
        (attempt_build_home / ".m2").mkdir(parents=True)
        if source_maven_repository is not None:
            shutil.copytree(
                source_maven_repository,
                attempt_build_home / ".m2" / "repository",
            )
        if source_maven_wrapper_dists is not None:
            shutil.copytree(
                source_maven_wrapper_dists,
                attempt_build_home / ".m2" / "wrapper" / "dists",
            )
        if source_gradle_user_home is not None:
            shutil.copytree(
                source_gradle_user_home,
                attempt_build_home / ".gradle",
            )
        else:
            (attempt_build_home / ".gradle").mkdir()
    elif source_gradle_user_home is not None:
        attempt_gradle_user_home = attempt_dir / "gradle-user-home"
        shutil.copytree(source_gradle_user_home, attempt_gradle_user_home)
    repaired_command, extra_env, applied = apply_repair_decision(
        original_command,
        validated,
        attempt_database_dir=database_dir,
        approved_java_homes=approved_java_homes,
        approved_maven_homes=approved_maven_homes,
        approved_ant_homes=approved_ant_homes,
        verified_gradle_user_home=attempt_gradle_user_home,
        isolated_build_home=attempt_build_home,
    )
    if Path(applied["source_root"]).resolve() != source_dir.resolve():
        raise RepairValidationError("repair attempted to change the exact source root")
    log_path = attempt_dir / "codeql-repair.log"
    with log_path.open("w", encoding="utf-8") as handle:
        handle.write("$ " + shlex.join(repaired_command) + "\n")
        handle.write(f"cwd={source_dir}\n")
        handle.flush()
        bounded = run_bounded_process(
            repaired_command,
            cwd=source_dir,
            env={**os.environ, **extra_env},
            timeout_seconds=timeout_seconds,
            term_grace_seconds=min(30, max(1, timeout_seconds / 20)),
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
    database_valid = valid_codeql_database(database_dir)
    status = "codeql_db_repaired" if bounded.returncode == 0 and database_valid else "repair_attempt_failed"
    final_packet = refresh_attempt_packet_log(packet, log_path=log_path)
    return {
        "schema_version": f"{SCHEMA_VERSION}:attempt",
        "recorded_at": utc_now(),
        "case_id": receipt.get("case_id"),
        "project_slug": receipt.get("project_slug"),
        "status": status,
        "packet": final_packet,
        "validated_decision": validated,
        "source_revision_evidence": source_evidence,
        "original_command_sha256": stable_json_sha256(original_command),
        "executed_command": repaired_command,
        "applied_repair": applied,
        "verified_gradle_user_home_source": (
            str(verified_gradle_user_home_source.resolve())
            if verified_gradle_user_home_source is not None
            else None
        ),
        "verified_maven_repository_source": (
            str(verified_maven_repository_source.resolve())
            if verified_maven_repository_source is not None
            else None
        ),
        "verified_maven_wrapper_dists_source": (
            str(verified_maven_wrapper_dists_source.resolve())
            if verified_maven_wrapper_dists_source is not None
            else None
        ),
        "isolated_build_home": (
            str(attempt_build_home.resolve()) if attempt_build_home is not None else None
        ),
        "bounded_process": bounded.to_dict(),
        "log_path": str(log_path),
        "log_sha256": sha256_file(log_path),
        "database_dir": str(database_dir),
        "database_valid": database_valid,
        "official_query_status": receipt.get("official_query_status"),
        "contract": {
            "exact_declared_source_verified": True,
            "source_revision_substitution_forbidden": True,
            "source_edits_forbidden": True,
            "official_query_change_forbidden": True,
            "new_attempt_database_only": True,
            "retrieval_and_target_data_not_consumed": True,
        },
    }
