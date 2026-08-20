from pathlib import Path

import hashlib

import pytest

from route_hacker.runtime.codeql_repair import (
    RepairValidationError,
    apply_repair_decision,
    build_repair_packet,
    classify_build_failure,
    heuristic_repair_decision,
    redact_text,
    source_integrity_snapshot,
    validate_repair_decision,
    verify_exact_source,
)


def failed_receipt(tmp_path: Path) -> dict:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    log_path = tmp_path / "failed.log"
    log_path.write_text(
        "BUILD FAILURE\n"
        "Failed to execute maven-enforcer-plugin:3.0.0-M3: "
        "java.lang.NoSuchMethodError API incompatibility\n"
        "API_KEY=should-not-leak\n",
        encoding="utf-8",
    )
    return {
        "case_id": "v8:example",
        "project_slug": "example",
        "resolved_buggy_commit": "abc123",
        "source_dir": str(source_dir),
        "planned_codeql_database_command": [
            "codeql",
            "database",
            "create",
            str(tmp_path / "old-db"),
            "--language=java",
            f"--source-root={source_dir}",
            "--overwrite",
            "--command",
            "mvn -DskipTests package",
        ],
        "codeql_database_create_result": {"log_path": str(log_path)},
    }


def source_snapshot_receipt(tmp_path: Path) -> dict:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    archive = tmp_path / "source.tar.gz"
    archive.write_bytes(b"archive-content")
    return {
        "case_id": "v8:example",
        "source_dir": str(source_dir),
        "resolved_buggy_commit": "abc123",
        "status": "source_materialized_exact_archive_snapshot",
        "contract": {"exact_declared_buggy_commit_only": True},
        "archive_result": {
            "archive_path": str(archive),
            "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "archive_url": "https://codeload.github.com/example/repo/tar.gz/abc123",
        },
    }


def test_packet_redacts_log_and_classifies_enforcer_failure(tmp_path):
    packet = build_repair_packet(
        failed_receipt(tmp_path),
        approved_java_homes=["/opt/java-17"],
        approved_maven_homes=["/opt/maven-3.8"],
    )

    assert packet["failed_attempt"]["failure_category"] == "maven_enforcer_api_incompatibility"
    assert "[REDACTED]" in packet["failed_attempt"]["log"]["excerpt"]
    assert "should-not-leak" not in packet["failed_attempt"]["log"]["excerpt"]
    assert packet["packet_sha256"]


def test_completed_attempt_packet_binds_final_log_and_failure_category(
    tmp_path,
    monkeypatch,
):
    receipt = failed_receipt(tmp_path)
    archive = tmp_path / "source.tar.gz"
    archive.write_bytes(b"archive-content")
    source_receipt = {
        "case_id": "v8:example",
        "source_dir": receipt["source_dir"],
        "resolved_buggy_commit": "abc123",
        "status": "source_materialized_exact_archive_snapshot",
        "contract": {"exact_declared_buggy_commit_only": True},
        "archive_result": {
            "archive_path": str(archive),
            "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "archive_url": "https://codeload.github.com/example/repo/tar.gz/abc123",
        },
    }

    class Result:
        returncode = 1

        def to_dict(self):
            return {"returncode": 1, "timed_out": False}

    def failed_process(*args, **kwargs):
        kwargs["stdout"].write("BUILD FAILURE\n")
        return Result()

    monkeypatch.setattr(
        "route_hacker.runtime.codeql_repair.run_bounded_process",
        failed_process,
    )
    from route_hacker.runtime.codeql_repair import execute_repair_attempt

    attempt = execute_repair_attempt(
        receipt,
        {"actions": [{"kind": "retry_same_command"}], "rationale": "retry"},
        attempt_dir=tmp_path / "attempt",
        timeout_seconds=10,
        approved_java_homes=[],
        approved_maven_homes=[],
        source_receipt=source_receipt,
    )

    packet = attempt["packet"]
    assert packet["failed_attempt"]["log"]["available"] is True
    assert packet["failed_attempt"]["log"]["path"] == attempt["log_path"]
    assert packet["failed_attempt"]["log"]["sha256"] == attempt["log_sha256"]
    assert packet["failed_attempt"]["failure_category"] == "generic_build_failure"
    assert packet["packet_sha256"]


def test_source_integrity_snapshot_ignores_generated_outputs_and_detects_source_change(
    tmp_path: Path,
):
    source = tmp_path / "source"
    source.mkdir()
    source_file = source / "src" / "Main.java"
    source_file.parent.mkdir()
    source_file.write_text("class Main {}\n", encoding="utf-8")
    before = source_integrity_snapshot(source)

    generated_file = source / "module" / "target" / "generated.txt"
    generated_file.parent.mkdir(parents=True)
    generated_file.write_text("generated\n", encoding="utf-8")
    shade_metadata = source / "module" / "dependency-reduced-pom.xml"
    shade_metadata.write_text("<project />\n", encoding="utf-8")
    flattened_metadata = source / "module" / ".flattened-pom.xml"
    flattened_metadata.write_text("<project />\n", encoding="utf-8")
    generated_only = source_integrity_snapshot(source)

    from route_hacker.runtime.codeql_repair import compare_source_integrity

    assert compare_source_integrity(before, generated_only)["verified"] is True
    assert generated_only["ignored_file_names"] == [
        ".flattened-pom.xml",
        "dependency-reduced-pom.xml",
    ]

    source_file.write_text("class Main { int changed; }\n", encoding="utf-8")
    changed = compare_source_integrity(before, source_integrity_snapshot(source))
    assert changed["verified"] is False
    assert changed["reason"] == "non_generated_source_content_changed_during_build"
    assert changed["changed_paths"] == ["src/Main.java"]


def test_execute_repair_rejects_database_when_build_changes_source_content(
    tmp_path: Path,
    monkeypatch,
):
    receipt = failed_receipt(tmp_path)
    source = Path(receipt["source_dir"])
    source_file = source / "Main.java"
    source_file.write_text("class Main {}\n", encoding="utf-8")
    archive = tmp_path / "source.tar.gz"
    archive.write_bytes(b"archive-content")
    source_receipt = {
        "case_id": "v8:example",
        "source_dir": receipt["source_dir"],
        "resolved_buggy_commit": "abc123",
        "status": "source_materialized_exact_archive_snapshot",
        "contract": {"exact_declared_buggy_commit_only": True},
        "archive_result": {
            "archive_path": str(archive),
            "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "archive_url": "https://codeload.github.com/example/repo/tar.gz/abc123",
        },
    }

    class Result:
        returncode = 0

        def to_dict(self):
            return {"returncode": 0, "timed_out": False}

    def mutating_process(*args, **kwargs):
        source_file.write_text("class Main { int changed; }\n", encoding="utf-8")
        database = tmp_path / "attempt" / "codeql-db"
        (database / "db-java" / "default").mkdir(parents=True)
        (database / "codeql-database.yml").write_text("name: test\n", encoding="utf-8")
        (database / "db-java" / "default" / "files.rel").write_bytes(b"relations")
        return Result()

    monkeypatch.setattr(
        "route_hacker.runtime.codeql_repair.run_bounded_process",
        mutating_process,
    )
    from route_hacker.runtime.codeql_repair import execute_repair_attempt

    attempt = execute_repair_attempt(
        receipt,
        {"actions": [{"kind": "retry_same_command"}], "rationale": "retry"},
        attempt_dir=tmp_path / "attempt",
        timeout_seconds=10,
        approved_java_homes=[],
        approved_maven_homes=[],
        source_receipt=source_receipt,
    )

    assert attempt["database_valid"] is True
    assert attempt["status"] == "repair_attempt_failed"
    assert attempt["source_integrity_evidence"]["verified"] is False
    assert attempt["source_integrity_evidence"]["changed_paths"] == ["Main.java"]


def test_execute_repair_attempt_copies_maven_wrapper_dists_into_isolated_home(
    tmp_path,
    monkeypatch,
):
    receipt = failed_receipt(tmp_path)
    archive = tmp_path / "source.tar.gz"
    archive.write_bytes(b"archive-content")
    source_receipt = {
        "case_id": "v8:example",
        "source_dir": receipt["source_dir"],
        "resolved_buggy_commit": "abc123",
        "status": "source_materialized_exact_archive_snapshot",
        "contract": {"exact_declared_buggy_commit_only": True},
        "archive_result": {
            "archive_path": str(archive),
            "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "archive_url": "https://codeload.github.com/example/repo/tar.gz/abc123",
        },
    }
    wrapper_dists = tmp_path / "wrapper-dists"
    cached_zip = (
        wrapper_dists
        / "apache-maven-3.5.0-bin"
        / "abc123"
        / "apache-maven-3.5.0-bin.zip"
    )
    cached_zip.parent.mkdir(parents=True)
    cached_zip.write_bytes(b"zip")

    class Result:
        returncode = 1

        def to_dict(self):
            return {"returncode": 1, "timed_out": False}

    def failed_process(*args, **kwargs):
        kwargs["stdout"].write("BUILD FAILURE\n")
        return Result()

    monkeypatch.setattr(
        "route_hacker.runtime.codeql_repair.run_bounded_process",
        failed_process,
    )
    from route_hacker.runtime.codeql_repair import execute_repair_attempt

    attempt = execute_repair_attempt(
        receipt,
        {"actions": [{"kind": "retry_same_command"}], "rationale": "retry"},
        attempt_dir=tmp_path / "attempt",
        timeout_seconds=10,
        approved_java_homes=[],
        approved_maven_homes=[],
        source_receipt=source_receipt,
        verified_maven_wrapper_dists_source=wrapper_dists,
        isolate_build_home=True,
    )

    copied_zip = (
        tmp_path
        / "attempt"
        / "build-home"
        / ".m2"
        / "wrapper"
        / "dists"
        / "apache-maven-3.5.0-bin"
        / "abc123"
        / "apache-maven-3.5.0-bin.zip"
    )
    assert copied_zip.read_bytes() == b"zip"
    assert attempt["verified_maven_wrapper_dists_source"] == str(wrapper_dists.resolve())
    assert attempt["isolated_build_home"] == str((tmp_path / "attempt" / "build-home").resolve())


def test_append_buildnumber_skip_arg_is_allowlisted_and_applied(tmp_path):
    receipt = failed_receipt(tmp_path)

    repaired, _env, applied = apply_repair_decision(
        receipt["planned_codeql_database_command"],
        validate_repair_decision(
            {
                "actions": [
                    {
                        "kind": "append_build_args",
                        "args": ["-Dmaven.buildNumber.skip=true"],
                    }
                ],
                "rationale": "skip buildnumber SCM metadata",
            },
            approved_java_homes=[],
            approved_maven_homes=[],
        ),
        attempt_database_dir=tmp_path / "new-db",
        approved_java_homes=[],
        approved_maven_homes=[],
    )

    assert "-Dmaven.buildNumber.skip=true" in repaired[-1]
    assert applied["build_command"] == [
        "mvn",
        "-DskipTests",
        "package",
        "-Dmaven.buildNumber.skip=true",
    ]


def test_source_snapshot_receipt_verifies_exact_archive_without_git_checkout(tmp_path):
    receipt = source_snapshot_receipt(tmp_path)

    evidence = verify_exact_source(
        tmp_path / "source",
        "abc123",
        receipt,
        expected_case_id="v8:example",
    )

    assert evidence["verified"] is True
    assert evidence["verification_mode"] == "source_snapshot_receipt"


def test_source_snapshot_receipt_rejects_wrong_revision(tmp_path):
    receipt = source_snapshot_receipt(tmp_path)

    evidence = verify_exact_source(
        tmp_path / "source",
        "not-the-expected-revision",
        receipt,
        expected_case_id="v8:example",
    )

    assert evidence["verified"] is False


def test_source_snapshot_receipt_rejects_case_mismatch(tmp_path):
    receipt = source_snapshot_receipt(tmp_path)

    evidence = verify_exact_source(
        tmp_path / "source",
        "abc123",
        receipt,
        expected_case_id="v8:other-case",
    )

    assert evidence["verified"] is False
    assert evidence["source_snapshot_receipt"]["reason"] == "source_receipt_case_id_mismatch"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Could not transfer artifact: Read timed out", "dependency_or_network"),
        (
            "Failed to execute goal io.github.git-commit-id:"
            "git-commit-id-maven-plugin:4.9.9:revision: "
            ".git directory is not found!",
            "maven_git_metadata_unavailable",
        ),
        (
            "Failed to execute goal org.codehaus.mojo:"
            "buildnumber-maven-plugin:1.4:create-metadata: "
            "Execution failed: NullPointerException",
            "maven_buildnumber_scm_metadata_unavailable",
        ),
        (
            "Downloaded from central: https://repo.maven.apache.org/maven2/example.jar\n"
            "Failed to execute goal org.codehaus.mojo:"
            "buildnumber-maven-plugin:3.2.1:create (default): "
            "Cannot get the revision information from the scm repository\n"
            "fatal: not a git repository",
            "maven_buildnumber_scm_metadata_unavailable",
        ),
        (
            "An exception occurred applying plugin request "
            "[id: 'junitbuild.build-metadata']\n"
            "Failed to apply plugin 'junitbuild.build-metadata'.\n"
            "Process 'command 'git'' finished with non-zero exit value 128",
            "gradle_scm_metadata_unavailable",
        ),
        (
            "Detected Maven Version: 3.5.0 is not in the allowed range [3.6.0,).",
            "maven_toolchain",
        ),
        (
            "Detected JDK version 21.0.11 is not in the allowed range [17.0,17.99].",
            "java_toolchain",
        ),
        (
            "Rule 4: RequireMavenVersion passed\n"
            "Detected JDK version 21.0.11 is not in the allowed range [17.0,17.99].",
            "java_toolchain",
        ),
        (
            "Could not resolve dependencies: org.example:base:jar:tests:"
            "1.0-SNAPSHOT (absent): Could not find artifact "
            "org.example:base:jar:tests:1.0-SNAPSHOT",
            "maven_reactor_artifact_phase",
        ),
        (
            "Could not resolve dependencies: org.example:base:jar:tests:"
            "1.0 (absent): Could not find artifact "
            "org.example:base:jar:tests:1.0 in central",
            "maven_reactor_artifact_phase",
        ),
        (
            "Failed to parse plugin descriptor for "
            "org.example:guides-maven-plugin:1.0 "
            "(/workspace/docs/maven-plugin/target/classes): "
            "No plugin descriptor found at META-INF/maven/plugin.xml",
            "maven_reactor_plugin_descriptor_phase",
        ),
        (
            "Artifact has not been packaged yet; it is part of the reactor, "
            "but the package phase has not been executed",
            "maven_reactor_package_phase",
        ),
        (
            "Failed to execute goal com.diffplug.spotless:spotless-maven-plugin:"
            "2.27.2:check: The following files had format violations",
            "maven_quality_gate",
        ),
        (
            "Failed to execute goal com.diffplug.spotless:spotless-maven-plugin:"
            "2.30.0:apply (spotless-apply) on project antisamy: "
            "Cannot find git repository in any parent directory",
            "maven_quality_gate",
        ),
        (
            "Failed to execute goal com.github.spotbugs:spotbugs-maven-plugin:"
            "4.2.2:spotbugs (spotbugs) on project rocketmq-common: "
            "java.lang.UnsupportedOperationException: "
            "The Security Manager is deprecated and will be removed",
            "maven_quality_gate",
        ),
        (
            "CodeQL detected code written in Java/Kotlin but could not process any of it.",
            "codeql_no_source_capture",
        ),
        ("Fatal error compiling: invalid flag: --release", "java_toolchain"),
        (
            "bad class file: AttributeExpression.class "
            "class file has wrong version 55.0, should be 52.0",
            "java_toolchain",
        ),
        ("Unsupported class file major version 65", "java_toolchain"),
        ("Runner failed to start 'ant': No such file or directory", "ant_toolchain"),
        ("./gradlew: Permission denied", "gradle_wrapper_or_path"),
        ("java.lang.OutOfMemoryError: Java heap space", "resource_exhaustion"),
        ("FAILURE: Build failed with an exception.", "generic_build_failure"),
    ],
)
def test_classify_build_failure(text, expected):
    assert classify_build_failure(text) == expected


def test_validate_repair_decision_rejects_arbitrary_command():
    with pytest.raises(RepairValidationError, match="unsupported repair action"):
        validate_repair_decision(
            {"actions": [{"kind": "run_shell", "command": "rm -rf /"}]},
            approved_java_homes=[],
            approved_maven_homes=[],
        )


def test_maven_toolchain_heuristic_uses_approved_selected_home(tmp_path):
    receipt = failed_receipt(tmp_path)
    Path(receipt["codeql_database_create_result"]["log_path"]).write_text(
        "BUILD FAILURE\nDetected Maven Version: 3.5.0 is not in the allowed range [3.6.0,).\n",
        encoding="utf-8",
    )
    packet = build_repair_packet(
        receipt,
        approved_java_homes=[],
        approved_maven_homes=["/opt/maven-3.9.8"],
    )

    decision = heuristic_repair_decision(
        packet,
        preferred_maven_home="/opt/maven-3.9.8",
    )
    validated = validate_repair_decision(
        decision,
        approved_java_homes=[],
        approved_maven_homes=["/opt/maven-3.9.8"],
    )

    assert validated["actions"] == [{"kind": "set_maven_home", "maven_home": "/opt/maven-3.9.8"}]


def test_git_metadata_heuristic_uses_versioned_plugin_skip_property(tmp_path):
    receipt = failed_receipt(tmp_path)
    Path(receipt["codeql_database_create_result"]["log_path"]).write_text(
        "BUILD FAILURE\n"
        "Failed to execute goal io.github.git-commit-id:"
        "git-commit-id-maven-plugin:4.9.9:revision: "
        ".git directory is not found!\n",
        encoding="utf-8",
    )
    packet = build_repair_packet(
        receipt,
        approved_java_homes=[],
        approved_maven_homes=[],
    )

    decision = heuristic_repair_decision(packet)
    validated = validate_repair_decision(
        decision,
        approved_java_homes=[],
        approved_maven_homes=[],
    )

    assert validated["actions"] == [
        {
            "kind": "append_build_args",
            "args": ["-Dmaven.gitcommitid.skip=true"],
        }
    ]


def test_buildnumber_metadata_heuristic_uses_plugin_skip_property(tmp_path):
    receipt = failed_receipt(tmp_path)
    Path(receipt["codeql_database_create_result"]["log_path"]).write_text(
        "BUILD FAILURE\n"
        "Failed to execute goal org.codehaus.mojo:"
        "buildnumber-maven-plugin:1.4:create-metadata: "
        "Execution failed: NullPointerException\n",
        encoding="utf-8",
    )
    packet = build_repair_packet(
        receipt,
        approved_java_homes=[],
        approved_maven_homes=[],
    )

    decision = heuristic_repair_decision(packet)
    validated = validate_repair_decision(
        decision,
        approved_java_homes=[],
        approved_maven_homes=[],
    )

    assert validated["actions"] == [
        {
            "kind": "append_build_args",
            "args": ["-Dmaven.buildNumber.skip=true"],
        }
    ]


def test_gradle_scm_metadata_heuristic_has_no_unsafe_archive_workaround(tmp_path):
    receipt = failed_receipt(tmp_path)
    Path(receipt["codeql_database_create_result"]["log_path"]).write_text(
        "FAILURE: Build failed with an exception.\n"
        "Failed to apply plugin 'junitbuild.build-metadata'.\n"
        "Process 'command 'git'' finished with non-zero exit value 128\n",
        encoding="utf-8",
    )
    packet = build_repair_packet(
        receipt,
        approved_java_homes=[],
        approved_maven_homes=[],
    )

    decision = heuristic_repair_decision(packet)
    validated = validate_repair_decision(
        decision,
        approved_java_homes=[],
        approved_maven_homes=[],
    )

    assert validated["actions"] == [{"kind": "no_safe_action"}]


def test_spotless_apply_skip_property_is_an_allowed_build_argument(tmp_path):
    validated = validate_repair_decision(
        {
            "schema_version": "route_hacker_codeql_repair.v1:repair_decision",
            "actions": [
                {
                    "kind": "append_build_args",
                    "args": ["-Dspotless.apply.skip=true"],
                }
            ],
            "rationale": "use the Spotless apply goal's declared skip property",
        },
        approved_java_homes=[],
        approved_maven_homes=[],
    )

    assert validated["actions"] == [
        {
            "kind": "append_build_args",
            "args": ["-Dspotless.apply.skip=true"],
        }
    ]


def test_quality_gate_heuristic_uses_only_allowlisted_skip_properties(tmp_path):
    receipt = failed_receipt(tmp_path)
    Path(receipt["codeql_database_create_result"]["log_path"]).write_text(
        "BUILD FAILURE\n"
        "Failed to execute goal com.diffplug.spotless:spotless-maven-plugin:"
        "2.27.2:check: The following files had format violations\n",
        encoding="utf-8",
    )
    packet = build_repair_packet(
        receipt,
        approved_java_homes=[],
        approved_maven_homes=[],
    )
    decision = heuristic_repair_decision(packet)
    validated = validate_repair_decision(
        decision,
        approved_java_homes=[],
        approved_maven_homes=[],
    )

    assert packet["failed_attempt"]["failure_category"] == "maven_quality_gate"
    assert validated["actions"] == [
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


def test_reactor_plugin_descriptor_phase_has_no_unproven_heuristic(tmp_path):
    receipt = failed_receipt(tmp_path)
    Path(receipt["codeql_database_create_result"]["log_path"]).write_text(
        "BUILD FAILURE\n"
        "Failed to parse plugin descriptor for "
        "org.example:guides-maven-plugin:1.0 "
        "(/workspace/docs/maven-plugin/target/classes): "
        "No plugin descriptor found at META-INF/maven/plugin.xml\n",
        encoding="utf-8",
    )
    packet = build_repair_packet(
        receipt,
        approved_java_homes=[],
        approved_maven_homes=[],
    )

    assert (
        packet["failed_attempt"]["failure_category"]
        == "maven_reactor_plugin_descriptor_phase"
    )
    assert heuristic_repair_decision(packet)["actions"] == [
        {"kind": "no_safe_action"}
    ]


def test_validate_repair_decision_rejects_unapproved_argument():
    with pytest.raises(RepairValidationError, match="unapproved argument"):
        validate_repair_decision(
            {"actions": [{"kind": "append_build_args", "args": ["-Ddangerous=true"]}]},
            approved_java_homes=[],
            approved_maven_homes=[],
        )


@pytest.mark.parametrize("argument", ["--no-daemon", "--stacktrace"])
def test_validate_repair_decision_rejects_gradle_only_argument(argument: str):
    with pytest.raises(RepairValidationError, match="unapproved argument"):
        validate_repair_decision(
            {"actions": [{"kind": "append_build_args", "args": [argument]}]},
            approved_java_homes=[],
            approved_maven_homes=[],
        )


def test_validate_repair_decision_drops_redundant_retry_same_command():
    validated = validate_repair_decision(
        {
            "actions": [
                {"kind": "retry_same_command"},
                {"kind": "set_maven_home", "maven_home": "/opt/maven-3.9.8"},
            ],
            "rationale": "Use the approved Maven version.",
        },
        approved_java_homes=[],
        approved_maven_homes=["/opt/maven-3.9.8"],
    )

    assert validated["actions"] == [
        {"kind": "set_maven_home", "maven_home": "/opt/maven-3.9.8"}
    ]
    assert validated["normalization"] == {
        "dropped_redundant_actions": ["retry_same_command"]
    }


@pytest.mark.parametrize(
    ("kind", "approved_key", "home_field", "home"),
    [
        ("set_java_home", "approved_java_homes", "java_home", "/opt/java-17"),
        ("set_maven_home", "approved_maven_homes", "maven_home", "/opt/maven-3.9.8"),
        ("set_ant_home", "approved_ant_homes", "ant_home", "/opt/ant-1.10"),
    ],
)
def test_validate_repair_decision_canonicalizes_approved_generic_home_value(
    kind: str,
    approved_key: str,
    home_field: str,
    home: str,
):
    approvals = {
        "approved_java_homes": [],
        "approved_maven_homes": [],
        "approved_ant_homes": [],
    }
    approvals[approved_key] = [home]

    validated = validate_repair_decision(
        {
            "actions": [{"kind": kind, "value": home}],
            "rationale": "Use the approved toolchain.",
        },
        **approvals,
    )

    assert validated["actions"] == [{"kind": kind, home_field: home}]


def test_validate_repair_decision_rejects_conflicting_home_value_fields():
    with pytest.raises(RepairValidationError, match="conflicting java_home and value"):
        validate_repair_decision(
            {
                "actions": [
                    {
                        "kind": "set_java_home",
                        "java_home": "/opt/java-17",
                        "value": "/opt/java-21",
                    }
                ],
                "rationale": "ambiguous toolchain",
            },
            approved_java_homes=["/opt/java-17", "/opt/java-21"],
            approved_maven_homes=[],
        )


def test_validate_repair_decision_merges_generic_build_argument_values():
    validated = validate_repair_decision(
        {
            "actions": [
                {"kind": "append_build_args", "value": "-Dcheckstyle.skip=true"},
                {"kind": "append_build_args", "value": "-Denforcer.skip=true"},
                {"kind": "append_build_args", "value": "-Dcheckstyle.skip=true"},
            ],
            "rationale": "Skip approved non-semantic quality gates.",
        },
        approved_java_homes=[],
        approved_maven_homes=[],
    )

    assert validated["actions"] == [
        {
            "kind": "append_build_args",
            "args": ["-Dcheckstyle.skip=true", "-Denforcer.skip=true"],
        }
    ]


def test_apply_repair_uses_new_database_and_preserves_source_root(tmp_path):
    receipt = failed_receipt(tmp_path)
    decision = validate_repair_decision(
        {
            "actions": [
                {"kind": "set_java_home", "java_home": "/opt/java-17"},
                {"kind": "append_build_args", "args": ["-Denforcer.skip=true"]},
            ],
            "rationale": "Enforcer compatibility only.",
        },
        approved_java_homes=["/opt/java-17"],
        approved_maven_homes=[],
    )

    command, env, applied = apply_repair_decision(
        receipt["planned_codeql_database_command"],
        decision,
        attempt_database_dir=tmp_path / "new-attempt-db",
        approved_java_homes=["/opt/java-17"],
        approved_maven_homes=[],
    )

    assert command[3] == str(tmp_path / "new-attempt-db")
    assert f"--source-root={tmp_path / 'source'}" in command
    assert "-Denforcer.skip=true" in command[command.index("--command") + 1]
    assert env["JAVA_HOME"] == "/opt/java-17"
    assert applied["source_root"] == str(tmp_path / "source")


def test_prepend_maven_clean_rebuilds_before_existing_package_goal(tmp_path):
    receipt = failed_receipt(tmp_path)
    decision = validate_repair_decision(
        {
            "actions": [
                {"kind": "prepend_maven_clean"},
                {"kind": "append_build_args", "args": ["-Dcheckstyle.skip=true"]},
            ],
            "rationale": "Force a fresh Maven compilation for CodeQL capture.",
        },
        approved_java_homes=[],
        approved_maven_homes=[],
    )

    command, _env, applied = apply_repair_decision(
        receipt["planned_codeql_database_command"],
        decision,
        attempt_database_dir=tmp_path / "new-attempt-db",
        approved_java_homes=[],
        approved_maven_homes=[],
    )

    build_command = command[command.index("--command") + 1]
    assert build_command == "mvn -DskipTests clean package -Dcheckstyle.skip=true"
    assert applied["applied_actions"][0] == {
        "kind": "prepend_maven_clean",
        "effect": "maven_clean_lifecycle_before_existing_build_goal",
    }


def test_remove_existing_build_args_only_removes_approved_present_argument(tmp_path):
    receipt = failed_receipt(tmp_path)
    receipt["planned_codeql_database_command"][-1] = (
        "mvn -DskipTests -Dmaven.test.skip=true package"
    )
    decision = validate_repair_decision(
        {
            "actions": [
                {
                    "kind": "remove_existing_build_args",
                    "args": ["-Dmaven.test.skip=true"],
                }
            ],
            "rationale": "Allow a required test-jar to be packaged.",
        },
        approved_java_homes=[],
        approved_maven_homes=[],
    )

    command, _env, applied = apply_repair_decision(
        receipt["planned_codeql_database_command"],
        decision,
        attempt_database_dir=tmp_path / "new-attempt-db",
        approved_java_homes=[],
        approved_maven_homes=[],
    )

    build_command = command[command.index("--command") + 1]
    assert build_command == "mvn -DskipTests package"
    assert applied["applied_actions"] == [
        {"kind": "remove_existing_build_args", "args": ["-Dmaven.test.skip=true"]}
    ]


def test_remove_existing_build_args_rejects_absent_argument(tmp_path):
    receipt = failed_receipt(tmp_path)
    decision = validate_repair_decision(
        {
            "actions": [
                {
                    "kind": "remove_existing_build_args",
                    "args": ["-Dmaven.test.skip=true"],
                }
            ],
            "rationale": "Do not rewrite arbitrary arguments.",
        },
        approved_java_homes=[],
        approved_maven_homes=[],
    )

    with pytest.raises(RepairValidationError, match="only remove arguments present"):
        apply_repair_decision(
            receipt["planned_codeql_database_command"],
            decision,
            attempt_database_dir=tmp_path / "new-attempt-db",
            approved_java_homes=[],
            approved_maven_homes=[],
        )


def test_prepend_maven_clean_rejects_non_maven_build_command(tmp_path):
    receipt = failed_receipt(tmp_path)
    receipt["planned_codeql_database_command"][-1] = "./gradlew build"
    decision = validate_repair_decision(
        {
            "actions": [{"kind": "prepend_maven_clean"}],
            "rationale": "This must not rewrite Gradle.",
        },
        approved_java_homes=[],
        approved_maven_homes=[],
    )

    with pytest.raises(RepairValidationError, match="direct Maven"):
        apply_repair_decision(
            receipt["planned_codeql_database_command"],
            decision,
            attempt_database_dir=tmp_path / "new-attempt-db",
            approved_java_homes=[],
            approved_maven_homes=[],
        )


def test_apply_repair_can_isolate_maven_user_home_without_changing_build_command(tmp_path):
    receipt = failed_receipt(tmp_path)
    build_home = tmp_path / "attempt-build-home"
    (build_home / ".m2").mkdir(parents=True)
    (build_home / ".gradle").mkdir()
    decision = validate_repair_decision(
        {"actions": [{"kind": "retry_same_command"}], "rationale": "retry"},
        approved_java_homes=[],
        approved_maven_homes=[],
    )

    command, env, applied = apply_repair_decision(
        receipt["planned_codeql_database_command"],
        decision,
        attempt_database_dir=tmp_path / "new-attempt-db",
        approved_java_homes=[],
        approved_maven_homes=[],
        isolated_build_home=build_home,
    )

    assert command[command.index("--command") + 1] == "mvn -DskipTests package"
    assert env["HOME"] == str(build_home)
    assert env["MAVEN_USER_HOME"] == str(build_home / ".m2")
    assert env["GRADLE_USER_HOME"] == str(build_home / ".gradle")
    assert f"-Duser.home={build_home}" in env["MAVEN_OPTS"]
    assert applied["verified_environment"]["GRADLE_USER_HOME"] == str(
        build_home / ".gradle"
    )
    assert applied["verified_environment"]["MAVEN_OPTS_user_home"] == (
        f"-Duser.home={build_home}"
    )


def test_execute_repair_seeds_verified_gradle_home_inside_isolated_build_home(
    tmp_path,
    monkeypatch,
):
    receipt = failed_receipt(tmp_path)
    verified_home = tmp_path / "verified-gradle-home"
    cached = (
        verified_home
        / "wrapper"
        / "dists"
        / "gradle-7.3.3-bin"
        / "wrapper-hash"
        / "gradle-7.3.3-bin.zip"
    )
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"verified-cache")

    class Result:
        returncode = 1

        def to_dict(self):
            return {"returncode": 1, "timed_out": False}

    monkeypatch.setattr(
        "route_hacker.runtime.codeql_repair.run_bounded_process",
        lambda *args, **kwargs: Result(),
    )
    archive = tmp_path / "attempt-source.tar.gz"
    archive.write_bytes(b"source")
    exact_source = {
        "case_id": "v8:example",
        "source_dir": receipt["source_dir"],
        "resolved_buggy_commit": "abc123",
        "status": "source_materialized_exact_archive_snapshot",
        "contract": {"exact_declared_buggy_commit_only": True},
        "archive_result": {
            "archive_path": str(archive),
            "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "archive_url": "https://codeload.github.com/example/repo/tar.gz/abc123",
        },
    }

    from route_hacker.runtime.codeql_repair import execute_repair_attempt

    attempt = execute_repair_attempt(
        receipt,
        {"actions": [{"kind": "retry_same_command"}], "rationale": "retry"},
        attempt_dir=tmp_path / "attempt",
        timeout_seconds=10,
        approved_java_homes=[],
        approved_maven_homes=[],
        source_receipt=exact_source,
        verified_gradle_user_home_source=verified_home,
        isolate_build_home=True,
    )

    copied = (
        Path(attempt["isolated_build_home"])
        / ".gradle"
        / cached.relative_to(verified_home)
    )
    assert copied.read_bytes() == b"verified-cache"
    assert attempt["applied_repair"]["verified_environment"]["GRADLE_USER_HOME"] == str(
        Path(attempt["isolated_build_home"]) / ".gradle"
    )


def test_execute_repair_seeds_verified_maven_repository_inside_isolated_home(
    tmp_path,
    monkeypatch,
):
    receipt = failed_receipt(tmp_path)
    verified_repository = tmp_path / "verified-maven-repository"
    cached = (
        verified_repository
        / "org"
        / "example"
        / "demo"
        / "1.0"
        / "demo-1.0.jar"
    )
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"verified-artifact")

    class Result:
        returncode = 1

        def to_dict(self):
            return {"returncode": 1, "timed_out": False}

    monkeypatch.setattr(
        "route_hacker.runtime.codeql_repair.run_bounded_process",
        lambda *args, **kwargs: Result(),
    )
    archive = tmp_path / "source.tar.gz"
    archive.write_bytes(b"archive-content")
    exact_source = {
        "case_id": "v8:example",
        "source_dir": receipt["source_dir"],
        "resolved_buggy_commit": "abc123",
        "status": "source_materialized_exact_archive_snapshot",
        "contract": {"exact_declared_buggy_commit_only": True},
        "archive_result": {
            "archive_path": str(archive),
            "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "archive_url": "https://codeload.github.com/example/repo/tar.gz/abc123",
        },
    }

    from route_hacker.runtime.codeql_repair import execute_repair_attempt

    attempt = execute_repair_attempt(
        receipt,
        {"actions": [{"kind": "retry_same_command"}], "rationale": "retry"},
        attempt_dir=tmp_path / "attempt",
        timeout_seconds=10,
        approved_java_homes=[],
        approved_maven_homes=[],
        source_receipt=exact_source,
        verified_maven_repository_source=verified_repository,
        isolate_build_home=True,
    )

    copied = (
        Path(attempt["isolated_build_home"])
        / ".m2"
        / "repository"
        / cached.relative_to(verified_repository)
    )
    assert copied.read_bytes() == b"verified-artifact"
    assert attempt["verified_maven_repository_source"] == str(verified_repository)


def test_apply_repair_uses_absolute_approved_maven_binary_for_mvn_command(tmp_path):
    receipt = failed_receipt(tmp_path)
    maven_home = tmp_path / "maven-3.9.8"
    maven_binary = maven_home / "bin" / "mvn"
    maven_binary.parent.mkdir(parents=True)
    maven_binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    maven_binary.chmod(0o755)
    decision = validate_repair_decision(
        {
            "actions": [{"kind": "set_maven_home", "maven_home": str(maven_home)}],
            "rationale": "Use the verified Maven binary.",
        },
        approved_java_homes=[],
        approved_maven_homes=[str(maven_home)],
    )

    command, env, applied = apply_repair_decision(
        receipt["planned_codeql_database_command"],
        decision,
        attempt_database_dir=tmp_path / "new-attempt-db",
        approved_java_homes=[],
        approved_maven_homes=[str(maven_home)],
    )

    assert command[command.index("--command") + 1].startswith(f"{maven_binary} ")
    assert env["MAVEN_HOME"] == str(maven_home)
    assert env["M2_HOME"] == str(maven_home)
    assert applied["applied_actions"] == [
        {
            "kind": "set_maven_home",
            "maven_home": str(maven_home),
            "maven_binary": str(maven_binary),
            "rewritten_build_executable": str(maven_binary),
        }
    ]


def test_apply_repair_allows_only_approved_ant_home(tmp_path):
    receipt = failed_receipt(tmp_path)
    ant_home = tmp_path / "apache-ant"
    (ant_home / "bin").mkdir(parents=True)
    decision = validate_repair_decision(
        {
            "actions": [{"kind": "set_ant_home", "ant_home": str(ant_home)}],
            "rationale": "Use the approved Ant toolchain.",
        },
        approved_java_homes=[],
        approved_maven_homes=[],
        approved_ant_homes=[str(ant_home)],
    )

    _, env, applied = apply_repair_decision(
        receipt["planned_codeql_database_command"],
        decision,
        attempt_database_dir=tmp_path / "new-attempt-db",
        approved_java_homes=[],
        approved_maven_homes=[],
        approved_ant_homes=[str(ant_home)],
    )

    assert env["ANT_HOME"] == str(ant_home)
    assert env["PATH"].startswith(f"{ant_home / 'bin'}:")
    assert applied["applied_actions"] == [
        {"kind": "set_ant_home", "ant_home": str(ant_home)}
    ]


def test_set_ant_home_rejects_an_unapproved_path():
    with pytest.raises(RepairValidationError, match="approved Ant home"):
        validate_repair_decision(
            {
                "actions": [{"kind": "set_ant_home", "ant_home": "/unapproved/ant"}],
                "rationale": "bad path",
            },
            approved_java_homes=[],
            approved_maven_homes=[],
            approved_ant_homes=[],
        )


def test_redact_text_removes_common_secret_shapes():
    value = redact_text("authorization: Bearer abc\npassword=secret\nnormal=true")

    assert "abc" not in value
    assert "secret" not in value
    assert "normal=true" in value
