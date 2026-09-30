#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["platformdirs"]
# ///
# ruff: noqa: S603 S607
"""Build a Docker runtime image for a benchmark repository.
NOTE: USE --network host to ensure network reachability

Usage examples
--------------
# Default mode: proxy auto-detected via 172.x bridge gateway (container network)
python3 scripts/build_repo_docker.py --repository output/intermediates/benchmark-repos/xwiki__xwiki-platform

# Host-network mode: proxy lives on 127.0.0.1 (host firewall blocks 172.x)
# Docker build runs with --network host so 127.0.0.1 is reachable inside the build
python3 scripts/build_repo_docker.py --host --repository output/intermediates/benchmark-repos/xwiki__xwiki-platform

# Host-network mode with explicit proxy port
python3 scripts/build_repo_docker.py --host --proxy 127.0.0.1:7891 --repository path/to/repo

# Bridge mode with explicit 172 gateway
python3 scripts/build_repo_docker.py --proxy 172.18.0.1:7890 --repository path/to/repo

# Disable proxy entirely (use mirror sources only)
python3 scripts/build_repo_docker.py --no-proxy --repository path/to/repo

# Dry-run: generate Dockerfile/prompt but do not build
python3 scripts/build_repo_docker.py --host --dry-run --repository path/to/repo

# Force rebuild of base image
python3 scripts/build_repo_docker.py --host --rebuild-base --repository path/to/repo

# Show current configuration
python3 scripts/build_repo_docker.py --config-show

The script:
  1. Selects proxy host: --host → 127.0.0.1 (with --network host build); default → 172.x bridge gateway
  2. Builds/reuses a base image with JDK, Maven, Gradle, miniconda, nvm
     Mirror sources (Tsinghua / Aliyun / npmmirror) are always configured to save bandwidth
  3. Calls `codex exec` non-interactively to generate a repo-specific Dockerfile and build it
  4. Tags the final image as route-hacker-repo/<repo_slug>:latest
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import textwrap
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import platformdirs

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent
APP_NAME = "route-hacker-docker"
BASE_IMAGE_NAME = "route-hacker-base"
REPO_IMAGE_PREFIX = "route-hacker-repo"

# ── Harness configuration ────────────────────────────────────────────────────
# codex (default)
CODEX_MODEL = "gpt-5.4-mini"

# claude / DeepSeek
CLAUDE_MODEL = "deepseek-v4-flash"
CLAUDE_BASE_URL = "https://api.deepseek.com/anthropic"
CLAUDE_AUTH_TOKEN = (
    os.environ.get("ANTHROPIC_AUTH_TOKEN")
    or os.environ.get("CLAUDE_AUTH_TOKEN")
    or os.environ.get("DEEPSEEK_API_KEY")
    or ""
)
# The OpenAI-compatible DeepSeek endpoint used for simple (non-agentic) API calls
CLAUDE_OPENAI_BASE_URL = "https://api.deepseek.com/v1"

# Ordered list of (host, port) pairs to probe in bridge mode (172.x gateway)
PROXY_PROBE_CANDIDATES_BRIDGE = [
    ("172.17.0.1", 2905),
    ("172.18.0.1", 2905),
    ("172.17.0.1", 7890),
    ("172.18.0.1", 7890),
    ("172.17.0.1", 7891),
    ("172.18.0.1", 7891),
    ("172.17.0.1", 1080),
    ("172.18.0.1", 1080),
    ("172.17.0.1", 8080),
    ("172.18.0.1", 8080),
]

# Ordered list of (host, port) pairs to probe in host-network mode (127.0.0.1)
PROXY_PROBE_CANDIDATES_HOST = [
    ("127.0.0.1", 2905),
    ("127.0.0.1", 7890),
    ("127.0.0.1", 7891),
    ("127.0.0.1", 1080),
    ("127.0.0.1", 8080),
]

DEFAULT_TOOLS = ["miniconda", "nvm"]
ALL_TOOLS = ["codeql", "miniconda", "nvm"]

# Default proxy snippets for each tool.  Placeholders: {proxy_url}, {proxy_host}, {proxy_port}
_DEFAULT_PROXY_MAP: dict[str, str] = {
    "apt": "RUN echo 'Acquire::http::Proxy \"{proxy_url}\";' > /etc/apt/apt.conf.d/99proxy \\\n    && echo 'Acquire::https::Proxy \"{proxy_url}\";' >> /etc/apt/apt.conf.d/99proxy \\\n    && echo 'Acquire::https::Verify-Peer \"false\";' >> /etc/apt/apt.conf.d/99proxy \\\n    && echo 'Acquire::https::Verify-Host \"false\";' >> /etc/apt/apt.conf.d/99proxy",
    "maven": "RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml <<'XML'\n<settings>\n  <proxies><proxy><id>main</id><active>true</active><protocol>http</protocol>\n    <host>{proxy_host}</host><port>{proxy_port}</port></proxy></proxies>\n</settings>\nXML",
    "gradle": "RUN mkdir -p /root/.gradle && printf 'systemProp.http.proxyHost={proxy_host}\\nsystemProp.http.proxyPort={proxy_port}\\nsystemProp.https.proxyHost={proxy_host}\\nsystemProp.https.proxyPort={proxy_port}\\n' > /root/.gradle/gradle.properties",
    "npm": "RUN npm config set proxy {proxy_url} && npm config set https-proxy {proxy_url}",
    "pip": "ENV PIP_INDEX_URL= \nENV PIP_PROXY={proxy_url}",
    "conda": "RUN conda config --set proxy_servers.http {proxy_url} --set proxy_servers.https {proxy_url}",
    "git": "RUN git config --global http.proxy {proxy_url} && git config --global https.proxy {proxy_url}",
    "curl": "ENV https_proxy={proxy_url}\nENV http_proxy={proxy_url}",
    "wget": "ENV http_proxy={proxy_url}\nENV https_proxy={proxy_url}",
    "nvm": "ENV HTTP_PROXY={proxy_url}\nENV HTTPS_PROXY={proxy_url}",
    "codeql": "ENV HTTPS_PROXY={proxy_url}\nENV HTTP_PROXY={proxy_url}",
    "cargo": "ENV HTTPS_PROXY={proxy_url}\nENV HTTP_PROXY={proxy_url}",
    "go": "ENV GOPROXY=direct\nENV HTTPS_PROXY={proxy_url}",
    "sbt": 'ENV SBT_OPTS="-Dhttp.proxyHost={proxy_host} -Dhttp.proxyPort={proxy_port} -Dhttps.proxyHost={proxy_host} -Dhttps.proxyPort={proxy_port}"',
}

# ──────────────────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class ProxyConfig:
    host: str
    port: int

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"


@dataclass
class AppConfig:
    proxy_host: str = ""
    proxy_port: int = 7890
    tools: list[str] = field(default_factory=lambda: list(DEFAULT_TOOLS))
    base_image: str = BASE_IMAGE_NAME


# ──────────────────────────────────────────────────────────────────────────────
# Base image tag generation
# ──────────────────────────────────────────────────────────────────────────────


def _base_image_tag(tools: list[str]) -> str:
    """Generate a deterministic tag based on tools configuration.

    The tag is based only on the tools list, not on proxy configuration.
    This allows the same base image to be reused across different proxy settings.

    Examples:
        tools=["miniconda", "nvm"] -> "tools-a1b2c3d4"
        tools=["codeql", "miniconda", "nvm"] -> "tools-e5f6g7h8"
    """
    if not tools:
        return "minimal"

    # Sort tools for deterministic hashing
    tools_str = ",".join(sorted(tools))
    hash_val = hashlib.sha256(tools_str.encode()).hexdigest()[:8]
    return f"tools-{hash_val}"


def _parse_tools_from_tag(tag: str) -> list[str]:
    """Parse tools list from a base image tag.

    This is a reverse operation of _base_image_tag, used for debugging.
    Returns empty list if tag format is not recognized.
    """
    # For now, we'll rely on image labels instead of parsing the tag
    return []


# ──────────────────────────────────────────────────────────────────────────────
# Logging setup
# ──────────────────────────────────────────────────────────────────────────────

logger = logging.getLogger(__name__)


def setup_logging(log_file: Optional[Path] = None) -> None:
    """Configure logging to stderr and optionally to a file."""
    logger.setLevel(logging.INFO)

    # Console handler (stderr)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter("[%(levelname)s] %(message)s")
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handler (if provided)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)


# ──────────────────────────────────────────────────────────────────────────────
# Config management (platformdirs + TOML)
# ──────────────────────────────────────────────────────────────────────────────


def _config_path() -> Path:
    return Path(platformdirs.user_config_dir(APP_NAME)) / "config.toml"


def _cache_dir() -> Path:
    return Path(platformdirs.user_cache_dir(APP_NAME))


def _data_dir() -> Path:
    return Path(platformdirs.user_data_dir(APP_NAME))


def _stage_build_assets(slug: str) -> Optional[Path]:
    """Copy per-repo build assets from platformdirs into the Docker build context.

    Source: <user_data_dir>/build-assets/<slug>/
    Dest:   <cwd>/assets/route_hacker/build-context/<slug>/

    Returns the dest path if assets were staged, None if no source assets exist.
    """
    src = _data_dir() / "build-assets" / slug
    if not src.is_dir():
        return None
    dest = Path.cwd() / "assets" / "route_hacker" / "build-context" / slug
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest)
    logger.info(f"Staged build assets: {src} → {dest}")
    return dest


def _load_toml(path: Path) -> dict:
    if sys.version_info >= (3, 11):
        import tomllib

        with path.open("rb") as f:
            return tomllib.load(f)
    try:
        import tomli  # type: ignore[import]

        with path.open("rb") as f:
            return tomli.load(f)
    except ImportError:
        # Minimal hand-rolled TOML parser for simple flat/section configs
        return _parse_simple_toml(path.read_text())


def _parse_simple_toml(text: str) -> dict:
    result: dict = {}
    section: dict = result
    section_name = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section_name = line[1:-1].strip()
            section = {}
            result[section_name] = section
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip()
            if v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            elif v.startswith("[") and v.endswith("]"):
                v = [x.strip().strip('"') for x in v[1:-1].split(",") if x.strip()]
            elif v.isdigit():
                v = int(v)
            section[k] = v
    return result


def _write_default_config(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        textwrap.dedent("""\
            [proxy]
            host = ""
            port = 7890

            [tools]
            enabled = ["miniconda", "nvm"]

            [docker]
            base_image = "route-hacker-base"
        """),
        encoding="utf-8",
    )


def load_config() -> AppConfig:
    path = _config_path()
    if not path.exists():
        return AppConfig()
    data = _load_toml(path)
    proxy = data.get("proxy", {})
    tools_section = data.get("tools", {})
    docker_section = data.get("docker", {})
    enabled = tools_section.get("enabled", DEFAULT_TOOLS)
    if isinstance(enabled, str):
        enabled = [x.strip() for x in enabled.split(",")]
    return AppConfig(
        proxy_host=proxy.get("host", ""),
        proxy_port=int(proxy.get("port", 7890)),
        tools=enabled,
        base_image=docker_section.get("base_image", BASE_IMAGE_NAME),
    )


def show_config(cfg: AppConfig) -> None:
    path = _config_path()
    cache = _cache_dir()
    proxy_map_path = _proxy_map_path()
    proxy_map_exists = proxy_map_path.exists()

    print(f"Config file : {path}")
    print(f"Cache dir   : {cache}")
    print(f"Proxy host  : {cfg.proxy_host or '(auto-detect)'}")
    print(f"Proxy port  : {cfg.proxy_port}")
    print(f"Tools       : {', '.join(cfg.tools) or '(none)'}")
    print(f"Base image  : {cfg.base_image}")
    print(
        f"Proxy map   : {proxy_map_path} {'(exists)' if proxy_map_exists else '(using built-in defaults)'}"
    )
    if not proxy_map_exists:
        print(f"              Run with --proxy-map-template to generate a customizable template")


# ──────────────────────────────────────────────────────────────────────────────
# Proxy map management
# ──────────────────────────────────────────────────────────────────────────────


def _proxy_map_path() -> Path:
    """Path to optional user proxy map override file."""
    return Path(platformdirs.user_config_dir(APP_NAME)) / "proxy_map.json"


def load_proxy_map() -> dict[str, str]:
    """Load proxy snippet map with fallback to defaults.

    Priority:
    1. User's proxy_map.json (if exists) - allows customization
    2. Built-in _DEFAULT_PROXY_MAP - always available

    This approach provides:
    - Sensible defaults that work out of the box
    - User customization when needed
    - No sync issues (defaults are in code)
    """
    # Start with built-in defaults
    proxy_map = dict(_DEFAULT_PROXY_MAP)

    # Override with user config if it exists
    user_config_path = _proxy_map_path()
    if user_config_path.exists():
        try:
            user_config = json.loads(user_config_path.read_text(encoding="utf-8"))
            if isinstance(user_config, dict):
                # Merge user config into defaults (user config takes precedence)
                proxy_map.update(user_config)
                logger.info(f"Loaded user proxy map overrides from {user_config_path}")
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"Failed to load user proxy map from {user_config_path}: {exc}")
            # Continue with defaults

    return proxy_map


def save_proxy_map_template() -> Path:
    """Save a template proxy_map.json for user customization.

    Returns the path to the saved file.
    """
    path = _proxy_map_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    # Create a comprehensive template with all built-in tools
    template = {
        "_comment": "Customize proxy configurations for build tools. "
        "Only add entries you want to override. Built-in defaults are used for missing entries.",
        "_usage": "Remove the underscore prefix from any tool name below to activate your custom configuration.",
        "_placeholders": "Available: {proxy_url}, {proxy_host}, {proxy_port}",
    }

    # Add all built-in tools as examples (with underscore prefix to disable by default)
    for tool, config in sorted(_DEFAULT_PROXY_MAP.items()):
        template[f"_{tool}"] = config

    # Add a note about how to enable
    template["_enable_example"] = "To customize 'apt', rename '_apt' to 'apt' and modify its value"

    path.write_text(json.dumps(template, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


# ──────────────────────────────────────────────────────────────────────────────
# Proxy detection
# ──────────────────────────────────────────────────────────────────────────────


def _parse_proxy_url(url: str) -> Optional[ProxyConfig]:
    """Extract host:port from a proxy URL like http://host:port or host:port."""
    url = url.strip()
    if not url:
        return None
    if "://" in url:
        url = url.split("://", 1)[1]
    url = url.rstrip("/")
    if ":" in url:
        host, _, port_str = url.rpartition(":")
        try:
            return ProxyConfig(host=host, port=int(port_str))
        except ValueError:
            return None
    return None


def _probe_proxy(host: str, port: int) -> bool:
    result = subprocess.run(
        [
            "curl",
            "--max-time",
            "2",
            "-s",
            "-o",
            "/dev/null",
            "-x",
            f"http://{host}:{port}",
            "-w",
            "%{http_code}",
            "http://example.com",
        ],
        capture_output=True,
        text=True,
    )
    code = result.stdout.strip()
    return bool(code and code != "000")


def _is_loopback_host(host: str) -> bool:
    return host.strip().lower() in {"127.0.0.1", "localhost", "::1"}


def _normalize_proxy_for_docker(proxy: Optional[ProxyConfig]) -> Optional[ProxyConfig]:
    """Map loopback proxy host to a docker-reachable bridge host, preserving port."""
    if not proxy or not _is_loopback_host(proxy.host):
        return proxy

    # Keep the original port and try common docker bridge gateway addresses first.
    bridge_hosts = ["172.17.0.1", "172.18.0.1"]
    for host in bridge_hosts:
        try:
            if _probe_proxy(host, proxy.port):
                return ProxyConfig(host=host, port=proxy.port)
        except Exception:  # noqa: BLE001
            continue

    # If bridge hosts are not reachable, keep loopback and rely on --network host during build.
    return proxy


def detect_proxy(
    cfg: AppConfig,
    override: Optional[str] = None,
    no_proxy: bool = False,
    host_mode: bool = False,
) -> Optional[ProxyConfig]:
    """Detect proxy configuration.

    In host_mode (--host flag), the proxy is expected on 127.0.0.1 and Docker
    builds run with --network host so the container can reach it.  In the
    default bridge mode the proxy must be reachable via the 172.x gateway.
    """
    if no_proxy:
        return None

    if override:
        pc = _parse_proxy_url(override)
        if pc:
            # In host mode keep loopback as-is; in bridge mode remap if needed.
            return pc if host_mode else _normalize_proxy_for_docker(pc)

    # Config file explicit host
    if cfg.proxy_host:
        pc = ProxyConfig(host=cfg.proxy_host, port=cfg.proxy_port)
        return pc if host_mode else _normalize_proxy_for_docker(pc)

    # Environment variables (case-insensitive, prefer uppercase)
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        val = os.environ.get(var, "")
        pc = _parse_proxy_url(val)
        if pc:
            return pc if host_mode else _normalize_proxy_for_docker(pc)

    # Auto-probe candidates depending on mode
    candidates = PROXY_PROBE_CANDIDATES_HOST if host_mode else PROXY_PROBE_CANDIDATES_BRIDGE
    for host, port in candidates:
        try:
            if _probe_proxy(host, port):
                pc = ProxyConfig(host=host, port=port)
                return pc if host_mode else _normalize_proxy_for_docker(pc)
        except Exception:  # noqa: BLE001
            continue

    return None


# ──────────────────────────────────────────────────────────────────────────────
# Build system detection
# ──────────────────────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────────────────────
# Build system detection
# ──────────────────────────────────────────────────────────────────────────────

# Fallback used when codex is unavailable
_BUILD_SYSTEM_MARKERS_FALLBACK = [
    ("pom.xml", "maven"),
    ("build.gradle", "gradle"),
    ("build.gradle.kts", "gradle"),
    ("package.json", "npm"),
    ("pyproject.toml", "python"),
    ("requirements.txt", "python"),
    ("Makefile", "make"),
    ("CMakeLists.txt", "cmake"),
]

_DETECT_PROMPT_TEMPLATE = """\
You are inspecting a repository to determine its build system(s).

Repository path: {repo_path}

List the files in the repository root and any sub-directories you find relevant.
Then output a JSON object to /tmp/rh_detect_{slug}.json with this shape:
{{
  "build_systems": ["maven"],       // ordered list, primary first; empty list if none
  "primary": "maven",               // primary build system or null
  "jdk_hint": "17",                 // detected JDK version string or null
  "notes": "..."                    // brief human-readable summary
}}

Valid build_system values: maven, gradle, npm, python, make, cmake, ant, sbt, bazel, cargo, go, dotnet, other, none
If the repo is empty or has no recognisable build system, use ["none"].
Write ONLY the JSON file; do not print anything else.
"""


def _detect_build_system_codex(repo_path: Path, codex_bin: str, dry_run: bool) -> list[str]:
    slug = repo_path.name
    # Use PID and timestamp for uniqueness in concurrent runs
    unique_id = f"{slug}_{os.getpid()}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
    out_file = Path(f"/tmp/rh_detect_{unique_id}.json")
    out_file.unlink(missing_ok=True)

    prompt = _DETECT_PROMPT_TEMPLATE.format(repo_path=str(repo_path.resolve()), slug=unique_id)
    cmd = [
        codex_bin,
        "exec",
        "--sandbox",
        "danger-full-access",
        "--model",
        CODEX_MODEL,
        "-c",
        "shell_environment_policy.inherit=all",
        "-c",
        'sandbox_permissions=["disk-full-read-access","network-full-access"]',
        "-",
    ]
    if dry_run:
        return []

    try:
        subprocess.run(cmd, input=prompt, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        logger.warning("codex build-system detection timed out; falling back to file markers")
        return []

    if out_file.exists():
        try:
            data = json.loads(out_file.read_text())
            systems = data.get("build_systems") or []
            return [s for s in systems if s and s != "none"]
        except Exception:  # noqa: BLE001
            pass
        finally:
            # Clean up temp file
            out_file.unlink(missing_ok=True)
    return []


def _detect_build_system_fallback(repo_path: Path) -> list[str]:
    found, seen = [], set()
    for marker, system in _BUILD_SYSTEM_MARKERS_FALLBACK:
        if (repo_path / marker).exists() and system not in seen:
            found.append(system)
            seen.add(system)
    return found


def detect_build_system(repo_path: Path, dry_run: bool = False) -> list[str]:
    """Return ordered list of detected build systems, using codex when available."""
    if dry_run:
        return _detect_build_system_fallback(repo_path)
    codex_bin = shutil.which("codex")
    if codex_bin:
        result = _detect_build_system_codex(repo_path, codex_bin, dry_run=False)
        if result:
            return result
    return _detect_build_system_fallback(repo_path)


# ──────────────────────────────────────────────────────────────────────────────
# Base image management
# ──────────────────────────────────────────────────────────────────────────────

_BASE_DOCKERFILE_TEMPLATE = """\
FROM ubuntu:22.04
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Tsinghua Ubuntu mirror (faster for CN networks)
RUN sed -i \
        's|http://archive.ubuntu.com/ubuntu/|http://mirrors.tuna.tsinghua.edu.cn/ubuntu/|g' \
        /etc/apt/sources.list \
    && sed -i \
        's|http://security.ubuntu.com/ubuntu/|http://mirrors.tuna.tsinghua.edu.cn/ubuntu/|g' \
        /etc/apt/sources.list

{apt_proxy}

RUN apt-get -o Acquire::Retries=6 update \
    && apt-get -o Acquire::Retries=6 install -y --fix-missing --no-install-recommends \
        ca-certificates curl wget git zip unzip gnupg lsb-release \\
        build-essential software-properties-common \\
    && rm -rf /var/lib/apt/lists/*

# Temurin JDK 8, 11, 17, 21
RUN mkdir -p /etc/apt/keyrings \
    && {apt_http_proxy} \\
       curl -fsSL --retry 3 --retry-delay 5 \\
           https://packages.adoptium.net/artifactory/api/gpg/key/public \\
           -o /tmp/adoptium-key.gpg \
    && gpg --dearmor -o /etc/apt/keyrings/adoptium.gpg /tmp/adoptium-key.gpg \
    && rm /tmp/adoptium-key.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/adoptium.gpg] \\
        https://packages.adoptium.net/artifactory/deb $(lsb_release -cs) main" \\
        > /etc/apt/sources.list.d/adoptium.list \
    && apt-get -o Acquire::Retries=6 update \
    && apt-get -o Acquire::Retries=6 install -y --fix-missing --no-install-recommends \
        temurin-8-jdk temurin-11-jdk temurin-17-jdk temurin-21-jdk \\
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Maven
RUN {apt_http_proxy} \\
    curl -fsSL --retry 3 --retry-delay 5 \\
        https://archive.apache.org/dist/maven/maven-3/3.9.11/binaries/apache-maven-3.9.11-bin.tar.gz \\
        | tar -xz -C /opt \\
    && ln -s /opt/apache-maven-3.9.11 /opt/maven
ENV PATH=/opt/maven/bin:$PATH

{mvn_proxy}

{miniconda_block}

{nvm_block}

{codeql_block}

# PyPI Tsinghua mirror
ENV PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
# Go module proxy
ENV GOPROXY=https://goproxy.cn,direct

# Metadata labels
LABEL tools="{tools_label}"
LABEL build_date="{build_date}"
LABEL base_image_version="2.0"

WORKDIR /workspace
"""

_MINICONDA_BLOCK = """\
# Miniconda
RUN {apt_http_proxy} \\
    curl -fsSL https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh \\
        -o /tmp/miniconda.sh \\
    && bash /tmp/miniconda.sh -b -p /opt/miniconda3 \\
    && rm /tmp/miniconda.sh
ENV PATH=/opt/miniconda3/bin:$PATH
RUN conda config --set always_yes yes --set changeps1 no \\
    && conda config --add channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/pkgs/main \\
    && conda config --add channels https://mirrors.tuna.tsinghua.edu.cn/anaconda/pkgs/r \\
    && conda config --set show_channel_urls yes{conda_proxy}
"""

_NVM_BLOCK = """\
# nvm
ENV NVM_DIR=/opt/nvm
RUN mkdir -p /opt/nvm \\
    && {apt_http_proxy} \\
       curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash \\
    && . /opt/nvm/nvm.sh \\
    && nvm install --lts \\
    && nvm alias default node \\
    && ln -s "$(dirname "$(dirname "$(nvm which default)")")" /opt/node-current
ENV PATH=/opt/node-current/bin:$PATH
# npmmirror (Taobao) registry
RUN npm config set registry https://registry.npmmirror.com
"""

_CODEQL_BLOCK = """\
# CodeQL CLI
RUN {apt_http_proxy} \\
    curl -fsSL https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz \\
        | tar -xz -C /opt \\
    && ln -s /opt/codeql/codeql /usr/local/bin/codeql
"""

def _render_base_dockerfile(proxy: Optional[ProxyConfig], tools: list[str]) -> str:
    proxy_url = proxy.url if proxy else ""
    proxy_map = load_proxy_map()

    def _snippet(tool: str) -> str:
        tmpl = proxy_map.get(tool, "")
        if not tmpl or not proxy:
            return ""
        return tmpl.format(proxy_url=proxy_url, proxy_host=proxy.host, proxy_port=proxy.port)

    apt_proxy = _snippet("apt") if proxy else ""
    # Trailing space is deliberate: when proxy is active this becomes an inline
    # env-var prefix (e.g. "https_proxy=... curl ..."); when empty the \ line
    # continuation still works and curl runs without prefix.
    apt_http_proxy = (
        f"https_proxy={proxy_url} http_proxy={proxy_url} HTTPS_PROXY={proxy_url} HTTP_PROXY={proxy_url} "
        if proxy
        else ""
    )

    # Maven settings: always include Aliyun central mirror; add proxy block when proxy is set.
    _mvn_proxy_block = ""
    if proxy:
        _mvn_proxy_block = (
            f"  <proxies><proxy><id>main</id><active>true</active><protocol>http</protocol>"
            f"<host>{proxy.host}</host><port>{proxy.port}</port></proxy></proxies>"
        )
    mvn_proxy = (
        "RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml <<'XML'\n"
        "<settings>\n"
        f"{_mvn_proxy_block}\n"
        "  <mirrors><mirror><id>aliyun-central</id>"
        "<mirrorOf>central</mirrorOf>"
        "<url>https://maven.aliyun.com/repository/central</url>"
        "</mirror></mirrors>\n"
        "</settings>\n"
        "XML"
    )
    conda_proxy = (
        f"\nRUN conda config --set proxy_servers.http {proxy_url} "
        f"--set proxy_servers.https {proxy_url}"
        if proxy
        else ""
    )

    miniconda_block = (
        _MINICONDA_BLOCK.format(apt_http_proxy=apt_http_proxy, conda_proxy=conda_proxy)
        if "miniconda" in tools
        else "# miniconda not enabled"
    )
    nvm_block = (
        _NVM_BLOCK.format(apt_http_proxy=apt_http_proxy)
        if "nvm" in tools
        else "# nvm not enabled"
    )
    codeql_block = (
        _CODEQL_BLOCK.format(apt_http_proxy=apt_http_proxy)
        if "codeql" in tools
        else "# codeql not enabled"
    )

    return _BASE_DOCKERFILE_TEMPLATE.format(
        apt_proxy=apt_proxy,
        apt_http_proxy=apt_http_proxy,
        mvn_proxy=mvn_proxy,
        miniconda_block=miniconda_block,
        nvm_block=nvm_block,
        codeql_block=codeql_block,
        tools_label=",".join(sorted(tools)) if tools else "minimal",
        build_date=datetime.now().isoformat(),
    )


def _base_marker_path() -> Path:
    return _cache_dir() / "base_built"


def _saved_dockerfile_path(slug: str, revision: Optional[str] = None) -> Path:
    """Get path to saved Dockerfile for a repository.

    Args:
        slug: Repository slug
        revision: Optional revision string

    Returns:
        Path to saved Dockerfile (includes revision in path if provided)
    """
    if revision:
        return _cache_dir() / "dockerfiles" / slug / revision / "Dockerfile"
    else:
        return _cache_dir() / "dockerfiles" / slug / "Dockerfile"


def _image_exists(name: str) -> bool:
    result = subprocess.run(
        ["docker", "image", "inspect", name],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _image_id(name: str) -> Optional[str]:
    result = subprocess.run(
        ["docker", "image", "inspect", name, "--format", "{{.Id}}"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    image_id = result.stdout.strip()
    return image_id or None


def _image_env_map(name: str) -> dict[str, str]:
    result = subprocess.run(
        ["docker", "image", "inspect", name, "--format", "{{json .Config.Env}}"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return {}
    raw = (result.stdout or "").strip()
    if not raw:
        return {}
    try:
        env_list = json.loads(raw)
    except Exception:  # noqa: BLE001
        return {}
    if not isinstance(env_list, list):
        return {}
    env_map: dict[str, str] = {}
    for entry in env_list:
        if not isinstance(entry, str) or "=" not in entry:
            continue
        key, value = entry.split("=", 1)
        env_map[key] = value
    return env_map


def _image_labels(name: str) -> dict[str, str]:
    """Get labels from a Docker image."""
    result = subprocess.run(
        ["docker", "image", "inspect", name, "--format", "{{json .Config.Labels}}"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return {}
    raw = (result.stdout or "").strip()
    if not raw or raw == "null":
        return {}
    try:
        labels = json.loads(raw)
        if isinstance(labels, dict):
            return labels
    except Exception:  # noqa: BLE001
        pass
    return {}


def _base_image_tools_match(image_name: str, required_tools: list[str]) -> bool:
    """Check if base image has all required tools.

    Returns True if the image has all required tools, False otherwise.
    """
    labels = _image_labels(image_name)
    tools_label = labels.get("tools", "")
    if not tools_label:
        # Old image without labels, assume mismatch
        return False

    existing_tools = set(tools_label.split(","))
    required_tools_set = set(required_tools)

    return required_tools_set.issubset(existing_tools)


def _needs_host_network(proxy: Optional[ProxyConfig], host_mode: bool) -> bool:
    """Return True if the docker build should use --network host.

    This is needed when:
    - host_mode is explicitly requested (proxy on 127.0.0.1), OR
    - the resolved proxy host is a loopback/bridge address that requires host
      networking to be reachable from inside the build container.
    """
    if host_mode:
        return True
    if not proxy:
        return False
    host = proxy.host.strip().lower()
    return host in {"127.0.0.1", "localhost", "::1", "172.17.0.1", "172.18.0.1"}


def _find_compatible_base_image(base_image_prefix: str, required_tools: list[str]) -> Optional[str]:
    """Find an existing base image that has all required tools.

    Returns the full image name (with tag) if found, None otherwise.
    Prefers images with fewer extra tools to minimize bloat.
    """
    # List all images with the base image prefix
    result = subprocess.run(
        ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}", base_image_prefix],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None

    candidates = []
    required_set = set(required_tools)

    for line in result.stdout.strip().split("\n"):
        if not line or ":" not in line:
            continue
        image_name = line.strip()
        if not image_name.startswith(base_image_prefix):
            continue

        # Check if this image has all required tools
        labels = _image_labels(image_name)
        tools_label = labels.get("tools", "")
        if not tools_label:
            continue

        existing_tools = set(tools_label.split(","))
        if required_set.issubset(existing_tools):
            # This image has all required tools
            extra_tools = len(existing_tools - required_set)
            candidates.append((image_name, extra_tools))

    if not candidates:
        return None

    # Sort by number of extra tools (prefer minimal bloat)
    candidates.sort(key=lambda x: x[1])
    return candidates[0][0]


def build_base_image(
    proxy: Optional[ProxyConfig],
    tools: list[str],
    base_image_prefix: str,
    rebuild: bool,
    dry_run: bool,
    host_mode: bool = False,
) -> tuple[bool, str]:
    """Build base image with specified tools.

    Returns:
        (success: bool, image_name: str) - The full image name with tag
    """
    tag = _base_image_tag(tools)
    base_image_full = f"{base_image_prefix}:{tag}"

    if not rebuild:
        # Check exact tag match first (avoids picking up -iris variant)
        if _image_exists(base_image_full):
            logger.info(
                f"Base image {base_image_full} already exists (use --rebuild-base to rebuild)"
            )
            return True, base_image_full

        # Then try to find any compatible image
        compatible_image = _find_compatible_base_image(base_image_prefix, tools)
        if compatible_image:
            logger.info(
                f"Found compatible base image: {compatible_image} (use --rebuild-base to rebuild)"
            )
            return True, compatible_image

    dockerfile_content = _render_base_dockerfile(proxy, tools)
    cache = _cache_dir()
    cache.mkdir(parents=True, exist_ok=True)
    dockerfile_path = cache / f"Dockerfile.base.{tag}"
    dockerfile_path.write_text(dockerfile_content, encoding="utf-8")

    logger.info(f"Base Dockerfile written to {dockerfile_path}")
    logger.info(f"Building base image: {base_image_full}")
    if dry_run:
        logger.info(
            f"[dry-run] Would run: docker build -t {base_image_full} -f {dockerfile_path} {cache}"
        )
        return True, base_image_full

    cmd = ["docker", "build"]
    if _needs_host_network(proxy, host_mode):
        # Host networking makes 127.0.0.1 (or bridge gateway) reachable inside build steps.
        cmd.extend(["--network", "host"])
    cmd.extend(["-t", base_image_full, "-f", str(dockerfile_path), str(cache)])
    logger.info(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, text=True)
    if result.returncode != 0:
        logger.error(f"Base image build failed (exit {result.returncode})")
        return False, base_image_full

    logger.info(f"Base image built: {base_image_full}")
    return True, base_image_full


# ──────────────────────────────────────────────────────────────────────────────
# Codex prompt generation
# ──────────────────────────────────────────────────────────────────────────────

_CODEX_PROMPT_TEMPLATE = """\
You are automating a Docker build pipeline. Your job is to create a working Docker image for a specific repository.

## Repository details
- Repo path on host: {repo_path}
- Docker build context path on host: {build_context}
- Detected build system(s): {build_systems}
- Target Docker image name: {image_name}
- Base image: {base_image}  (already built; has JDK 8/11/17/21, Maven, Gradle wrapper support{optional_tools})
- Build directory: {build_dir}
- Build cache directory: {build_cache_dir}
- Debug container: {container_name}
- Platform cache preparation: `{build_cache_prep}`
- Platform cache mounts: `{build_cache_mounts}`

Known JDK homes in the base image:
- /usr/lib/jvm/temurin-8-jdk-amd64
- /usr/lib/jvm/temurin-11-jdk-amd64
- /usr/lib/jvm/temurin-17-jdk-amd64
- /usr/lib/jvm/temurin-21-jdk-amd64

## Proxy configuration
{proxy_section}

{assets_section}{existing_dockerfile_section}{reference_dockerfile_section}## Your task

### Strategy: Interactive container-based build

Use a running container to interactively fix compilation issues, then write a Dockerfile that reproduces the successful build.

#### Step 1: Use the platform-prepared debug container
```bash
CONTAINER={container_name}
docker ps --format '{{{{.Names}}}}' | grep -Fx "$CONTAINER"
docker inspect $CONTAINER --format '{{{{json .Mounts}}}}'
docker exec $CONTAINER bash -c "test -d /workspace/repo && test -d /root/.m2/repository && test -d /root/.gradle/caches && test -d /root/.gradle/wrapper"
```
The route-hacker platform already created this container, copied the repository
into `/workspace/repo`, and mounted persistent Maven/Gradle caches from the host.
Do not recreate the container unless it is missing.

#### Step 2: Inspect the repository inside the container
```bash
docker exec $CONTAINER bash -c "ls /workspace/repo"
docker exec $CONTAINER bash -c "cat /workspace/repo/pom.xml 2>/dev/null | head -80 || cat /workspace/repo/build.gradle 2>/dev/null | head -50"
```
Determine:
- Exact build system and required JDK version (check pom.xml `<java.version>` / `<source>` / `<maven.compiler.source>`, or build.gradle `sourceCompatibility`)
- Build command (prefer `mvn -B -DskipTests compile`; use `install` only if needed for multi-module SNAPSHOT deps)
- Whether Maven wrapper (`mvnw`) or Gradle wrapper (`gradlew`) is present

#### Step 3: Try to build inside the container
Set JAVA_HOME to the detected version and run the build.
**To avoid flooding your context with verbose output, tee all build output to a log file and only
read the tail. The full log remains on disk for you to inspect if needed.**
```bash
BUILD_LOG={build_dir}/build.log
mkdir -p {build_dir}
docker exec $CONTAINER bash -c "export JAVA_HOME=<detected_jdk_path> && export PATH=\$JAVA_HOME/bin:\$PATH && cd /workspace/repo && <build command>" 2>&1 | tee "$BUILD_LOG" | tail -50
```
The log is written to the **host** at `$BUILD_LOG` (outside the container), so it persists after the container is removed.
- If the tail shows a clean success (e.g. `BUILD SUCCESS`), proceed to Step 5.
- If it shows errors or warnings that need investigation, read more of the log:
  ```bash
  grep -E "ERROR|WARN|FAILURE" "$BUILD_LOG" | tail -30
  # or read a specific range:
  tail -200 "$BUILD_LOG"
  ```
{gradle_proxy_hint_exec}

#### Step 4: Fix issues iteratively (max 5 attempts)
If the build fails, diagnose and fix inside the container:
- Missing packages: `docker exec $CONTAINER apt-get install -y <package>`
- Wrong JDK: switch JAVA_HOME to a different temurin version
- Maven proxy issues: `docker exec $CONTAINER bash -c "cat /root/.m2/settings.xml"`
- Gradle proxy: `docker exec $CONTAINER bash -c "cat /root/.gradle/gradle.properties"`
- Maven multi-module SNAPSHOT: switch from `compile` to `mvn -B -DskipTests install`

For each failed attempt, show only the relevant error lines (from the log grep above), not the full output.

#### Step 5: Once build succeeds, write a Dockerfile
Based on what worked in the container, write `{build_dir}/Dockerfile`:
```dockerfile
# syntax=docker/dockerfile:1.7
FROM {base_image}
{proxy_env_lines}
# Set correct JAVA_HOME for detected JDK version
ENV JAVA_HOME=<detected_jdk_path>
ENV PATH=$JAVA_HOME/bin:$PATH
# Any additional setup that was needed (apt installs, config files, etc.)
{gradle_proxy_hint}
COPY {repo_copy_path} /workspace/repo
WORKDIR /workspace/repo
# Prefer BuildKit cache mounts for Maven/Gradle downloads, for example:
# RUN --mount=type=cache,target=/root/.m2/repository <exact Maven command that worked>
# RUN --mount=type=cache,target=/root/.gradle/caches --mount=type=cache,target=/root/.gradle/wrapper <exact Gradle command that worked>
RUN <exact build command that worked>
```
IMPORTANT: `COPY` source must be relative to Docker build context and MUST NOT be an absolute host path.

#### Step 6: Build the final image from the Dockerfile
```bash
DOCKER_LOG={build_dir}/docker_build.log
mkdir -p {build_dir}
DOCKER_BUILDKIT=1 docker build --quiet {docker_build_network_flag} -t {image_name} -f {build_dir}/Dockerfile {build_context} 2>&1 | tee "$DOCKER_LOG" | tail -20
```
The log is written to the **host** at `$DOCKER_LOG`.
If build fails, read errors from the log rather than rerunning without --quiet:
```bash
grep -E "^ERROR|^Step|failed to" "$DOCKER_LOG" | tail -30
```
Max 3 attempts.

#### Step 7: Verify and clean up
```bash
docker image inspect {image_name}
docker rm -f $CONTAINER
```
Only if inspect succeeds, print exactly: CODEX_BUILD_SUCCESS {image_name}
On failure after retries, print exactly: CODEX_BUILD_FAILED <reason>

IMPORTANT: Never print CODEX_BUILD_SUCCESS unless `docker image inspect` succeeds.
IMPORTANT: If codeql is in the tool list, CODEX_BUILD_SUCCESS also requires
           `docker run --rm {image_name} test -d /codeql-db` to pass.

{deadline_section}{codeql_section}{extra_prompt_section}## Per-tool proxy snippets for reference
{proxy_snippets_section}
"""


def _build_codex_prompt(
    repo_path: Path,
    build_context: Path,
    repo_copy_path: str,
    docker_build_network_flag: str,
    build_systems: list[str],
    image_name: str,
    base_image: str,
    proxy: Optional[ProxyConfig],
    tools: list[str],
    build_dir: Path,
    existing_dockerfile: bool = False,
    reference_dockerfiles: Optional[list[Path]] = None,
    deadline_unix: Optional[int] = None,
    extra_prompt: Optional[str] = None,
    staged_assets_dir: Optional[Path] = None,
    build_cache_dir: Optional[Path] = None,
    container_name: Optional[str] = None,
) -> str:
    slug = repo_path.name
    if container_name is None:
        container_name = f"rh_fix_{slug}_{os.getpid()}"
    proxy_host = proxy.host if proxy else ""
    proxy_port = str(proxy.port) if proxy else ""
    proxy_url = proxy.url if proxy else ""

    proxy_map = load_proxy_map()

    if proxy:
        proxy_section = textwrap.dedent(f"""\
            Proxy is available at {proxy.url}.
            The base image already sets HTTP_PROXY/HTTPS_PROXY env vars and Maven settings.xml.
            You MUST also configure the build tool's own proxy if it doesn't use env vars (e.g. Gradle).
        """)
        proxy_env_lines = f"ENV HTTP_PROXY={proxy_url}\nENV HTTPS_PROXY={proxy_url}"
        gradle_proxy_hint = proxy_map.get("gradle", "").format(
            proxy_url=proxy_url, proxy_host=proxy_host, proxy_port=proxy_port
        )
        gradle_proxy_hint_exec = (
            f"If using Gradle, configure proxy inside the container first:\n"
            f"```bash\n"
            f'docker exec $CONTAINER bash -c "mkdir -p /root/.gradle && '
            f"printf 'systemProp.http.proxyHost={proxy_host}\\\\nsystemProp.http.proxyPort={proxy_port}\\\\n"
            f"systemProp.https.proxyHost={proxy_host}\\\\nsystemProp.https.proxyPort={proxy_port}\\\\n' "
            f'> /root/.gradle/gradle.properties"\n'
            f"```"
        )
    else:
        proxy_section = "No proxy detected. Build will connect directly."
        proxy_env_lines = ""
        gradle_proxy_hint = ""
        gradle_proxy_hint_exec = ""

    optional_tools_str = ""
    if tools:
        optional_tools_str = ", " + ", ".join(tools)

    # Build per-tool proxy reference section from proxy_map
    proxy_snippets_lines = []
    if proxy:
        for tool, tmpl in proxy_map.items():
            if tool in ("apt",):
                continue  # apt handled in base image
            snippet = tmpl.format(proxy_url=proxy_url, proxy_host=proxy_host, proxy_port=proxy_port)
            proxy_snippets_lines.append(f"- {tool}:\n  ```\n  {snippet}\n  ```")
    proxy_snippets_section = (
        "\n".join(proxy_snippets_lines) if proxy_snippets_lines else "(no proxy)"
    )

    if existing_dockerfile:
        existing_dockerfile_section = (
            "## Existing Dockerfile (try first)\n"
            f"A Dockerfile from a previous successful build is already at `{build_dir}/Dockerfile`.\n"
            "**Try building with it directly first** — skip the container approach unless the build fails:\n"
            "```bash\n"
            f"docker build --quiet {docker_build_network_flag} -t {image_name}"
            f" -f {build_dir}/Dockerfile {build_context}\n"
            "```\n"
            "Note: --quiet flag reduces verbose output. If build fails, retry without --quiet for debugging.\n"
            "If the build succeeds, verify with `docker image inspect` and report CODEX_BUILD_SUCCESS as usual.\n"
            "If it fails, fall back to the interactive container strategy below.\n\n"
        )
    else:
        existing_dockerfile_section = ""

    if reference_dockerfiles and not existing_dockerfile:
        lines = [
            "## Reference Dockerfiles (from successful builds of other revisions)\n\n",
            "The following Dockerfiles successfully built different revisions of this repository.\n",
            "They are listed most-recent-build first — the first entry is usually from the most\n",
            "adjacent commit (e.g. the before-patch / post-patch counterpart) and is the best\n",
            "starting point. Use `cat <path>` to read whichever revision looks closest to the\n",
            "current one, then adapt it. Do not follow them blindly — only use as a starting\n",
            "point if the approach seems applicable.\n\n",
        ]
        for df in reference_dockerfiles:
            rev = df.parent.name
            notes_path = df.parent / "build-notes.md"
            notes_hint = f" (build notes: `{notes_path}`)" if notes_path.exists() else ""
            lines.append(f"- revision `{rev}`: `{df}`{notes_hint}\n")
        lines.append("\n")
        reference_dockerfile_section = "".join(lines)
    else:
        reference_dockerfile_section = ""

    if "codeql" in tools:
        codeql_section = textwrap.dedent(f"""\
            ## CodeQL analysis — MANDATORY, NON-NEGOTIABLE
            **The task is INCOMPLETE without this step. Do NOT skip it.**

            The base image has CodeQL CLI installed at `/usr/local/bin/codeql`.
            After the `docker build` succeeds, add a **final RUN block** to the Dockerfile:

            ```dockerfile
            # MANDATORY: CodeQL database + security scan
            RUN mkdir -p /codeql-results \\
                && cd /workspace/repo \\
                && codeql database create /codeql-db \\
                    --language=java-kotlin \\
                    --source-root=/workspace/repo \\
                    --command="<SAME-BUILD-COMMAND-AS-ABOVE>" \\
                    --overwrite \\
                && codeql database analyze /codeql-db \\
                    --format=sarifv2.1.0 \\
                    --output=/codeql-results/results.sarif \\
                    -- /opt/codeql/qlpacks/codeql/java-queries/codeql-suites/java-security-and-quality.qls
            ```

            - ``--command``: use the **exact same** build command from the compile step
              (e.g. ``mvn -B -DskipTests compile`` or ``./gradlew compileJava``).
            - This is a **hard gate** — do NOT print CODEX_BUILD_SUCCESS unless
              `docker run --rm {image_name} test -d /codeql-db` succeeds.
            - If the CodeQL step fails, add it to the retry count and fix the issue.
            - Never skip this step for any reason — a build without CodeQL is a FAILED build.

            """)
    else:
        codeql_section = ""

    if deadline_unix is not None:
        deadline_iso = datetime.fromtimestamp(deadline_unix).isoformat(timespec="seconds")
        deadline_section = textwrap.dedent(f"""\
            ## Time budget
            Session deadline: {deadline_iso} (Unix: {deadline_unix})
            After this deadline, do NOT start any new build commands or docker operations.
            Instead: wait for any currently-running command to finish, then run
            `docker image inspect {image_name}` to verify, and report CODEX_BUILD_SUCCESS or CODEX_BUILD_FAILED.

            """)
    else:
        deadline_section = ""

    if extra_prompt:
        extra_prompt_section = "## Additional instructions\n" + extra_prompt.strip() + "\n\n"
    else:
        extra_prompt_section = ""

    if staged_assets_dir is not None:
        try:
            assets_rel = str(staged_assets_dir.relative_to(build_context))
            assets_section = (
                "## Pre-staged build assets\n"
                f"Host path (relative to build context): `{assets_rel}/`\n"
                "These files are already inside the Docker build context and can be used directly "
                "in Dockerfile `COPY` instructions.\n"
                f"Example: `COPY {assets_rel}/xwiki-commons-bootstrap /workspace/xwiki-commons-bootstrap`\n\n"
            )
        except ValueError:
            assets_section = ""
    else:
        assets_section = ""

    if build_cache_dir is None:
        build_cache_dir = _repo_build_cache_dir(slug)
    build_cache_prep, build_cache_mounts = _repo_build_cache_shell(build_cache_dir)

    return _CODEX_PROMPT_TEMPLATE.format(
        repo_path=str(repo_path.resolve()),
        build_context=str(build_context),
        repo_copy_path=repo_copy_path,
        docker_build_network_flag=docker_build_network_flag,
        docker_run_network_flag="--network host" if docker_build_network_flag else "",
        build_systems=", ".join(build_systems) if build_systems else "unknown",
        image_name=image_name,
        base_image=base_image,
        optional_tools=optional_tools_str,
        proxy_section=proxy_section,
        proxy_env_lines=proxy_env_lines,
        gradle_proxy_hint=gradle_proxy_hint,
        gradle_proxy_hint_exec=gradle_proxy_hint_exec,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        proxy_url=proxy_url,
        slug=slug,
        pid=os.getpid(),
        build_dir=str(build_dir),
        build_cache_dir=str(build_cache_dir),
        container_name=container_name,
        build_cache_prep=build_cache_prep,
        build_cache_mounts=build_cache_mounts,
        proxy_snippets_section=proxy_snippets_section,
        existing_dockerfile_section=existing_dockerfile_section,
        reference_dockerfile_section=reference_dockerfile_section,
        assets_section=assets_section,
        codeql_section=codeql_section,
        deadline_section=deadline_section,
        extra_prompt_section=extra_prompt_section,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Codex execution
# ──────────────────────────────────────────────────────────────────────────────


NO_COMPILE_MARKER = ".no-compile"


def _get_build_dir(slug: str) -> Path:
    """Get a unique build directory for this process.

    Uses PID to ensure concurrent builds don't conflict.
    """
    return Path(f"/tmp/rh_build_{slug}_{os.getpid()}")


def _repo_build_cache_dir(slug: str) -> Path:
    """Return the persistent host-side dependency cache for one repo slug."""
    return _cache_dir() / "repo-build-cache" / slug


def _repo_build_cache_shell(cache_dir: Path) -> tuple[str, str]:
    """Return shell snippets for preparing and mounting build dependency caches."""
    cache_dir = cache_dir.resolve()
    m2_dir = cache_dir / "m2-repository"
    gradle_caches_dir = cache_dir / "gradle-caches"
    gradle_wrapper_dir = cache_dir / "gradle-wrapper"
    prep = (
        f"mkdir -p {m2_dir} {gradle_caches_dir} {gradle_wrapper_dir}"
    )
    mounts = " ".join(
        [
            f"-v {m2_dir}:/root/.m2/repository",
            f"-v {gradle_caches_dir}:/root/.gradle/caches",
            f"-v {gradle_wrapper_dir}:/root/.gradle/wrapper",
        ]
    )
    return prep, mounts


def _prepare_debug_container(
    *,
    repo_path: Path,
    slug: str,
    base_image: str,
    docker_run_network_flag: str,
    build_cache_dir: Path,
    dry_run: bool,
) -> str:
    """Create the debug container with platform-controlled dependency caches."""
    container_name = f"rh_fix_{slug}_{os.getpid()}"
    prep, mounts = _repo_build_cache_shell(build_cache_dir)
    if dry_run:
        logger.info("[dry-run] Would prepare debug container: %s", container_name)
        logger.info("[dry-run] %s", prep)
        logger.info(
            "[dry-run] docker run -d --name %s %s %s %s sleep infinity",
            container_name,
            docker_run_network_flag,
            mounts,
            base_image,
        )
        logger.info("[dry-run] docker cp %s %s:/workspace/repo", repo_path, container_name)
        return container_name

    subprocess.run(["bash", "-lc", prep], check=True)
    subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cmd = f"docker run -d --name {container_name} {docker_run_network_flag} {mounts} {base_image} sleep infinity"
    logger.info("Preparing debug container: %s", cmd)
    subprocess.run(["bash", "-lc", cmd], check=True)
    subprocess.run(["docker", "cp", str(repo_path), f"{container_name}:/workspace/repo"], check=True)
    subprocess.run(
        [
            "docker",
            "exec",
            container_name,
            "bash",
            "-lc",
            "test -d /workspace/repo && test -d /root/.m2/repository && test -d /root/.gradle/caches && test -d /root/.gradle/wrapper",
        ],
        check=True,
    )
    return container_name


def _is_no_compile_repo(repo_path: Path) -> bool:
    """Return True if the repo is empty or contains a .no-compile marker."""
    marker = repo_path / NO_COMPILE_MARKER
    if marker.exists():
        return True
    entries = [p for p in repo_path.iterdir() if not p.name.startswith(".")]
    return len(entries) == 0


def build_trivial_repo_image(
    repo_path: Path,
    image_name: str,
    base_image: str,
    dry_run: bool,
    host_mode: bool = False,
) -> bool:
    """Build a minimal image (FROM base only) to test the base environment."""
    slug = repo_path.name
    build_dir = _get_build_dir(slug)
    build_dir.mkdir(parents=True, exist_ok=True)
    dockerfile = build_dir / "Dockerfile"
    dockerfile.write_text(f"FROM {base_image}\nWORKDIR /workspace\n", encoding="utf-8")

    logger.info(f"No-compile mode: wrote trivial Dockerfile to {dockerfile}")
    if dry_run:
        logger.info(
            f"[dry-run] Would run: docker build -t {image_name} -f {dockerfile} {build_dir}"
        )
        return True

    cmd = ["docker", "build"]
    if host_mode:
        cmd.extend(["--network", "host"])
    cmd.extend(["-t", image_name, "-f", str(dockerfile), str(build_dir)])
    logger.info(f"Building trivial repo image: {' '.join(cmd)}")
    result = subprocess.run(cmd, text=True)
    if result.returncode != 0:
        logger.error(f"Trivial image build failed (exit {result.returncode})")
        return False
    logger.info(f"Trivial image built: {image_name}")
    return True


def run_codex(prompt: str, dry_run: bool, image_name: str) -> bool:
    codex_bin = shutil.which("codex")
    if not codex_bin:
        logger.error("codex exec not found in PATH. Install it with: npm install -g @openai/codex")
        return False

    cmd = [
        codex_bin,
        "exec",
        "--sandbox",
        "danger-full-access",
        "--model",
        CODEX_MODEL,
        "-c",
        "shell_environment_policy.inherit=all",
        "-c",
        'sandbox_permissions=["disk-full-read-access","network-full-access"]',
        "-c",
        "truncation_policy={mode='tokens',limit=100000}",
        "-",
    ]
    logger.info(f"Running codex: {codex_bin} exec --model {CODEX_MODEL} --truncation 100k ...")
    if dry_run:
        logger.info("[dry-run] Prompt prepared in memory")
        logger.info("[dry-run] Would run codex; skipping.")
        return True

    import threading

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    proc.stdin.write(prompt)
    proc.stdin.close()

    def _stream() -> None:
        for line in proc.stdout:  # type: ignore[union-attr]
            stripped = line.rstrip()
            logger.info(stripped)
            print(stripped, flush=True)

    t = threading.Thread(target=_stream, daemon=True)
    t.start()
    t.join()
    proc.wait()

    if proc.returncode != 0:
        logger.error(f"codex exec exited with code {proc.returncode}")
        return False

    if not _image_exists(image_name):
        logger.error("codex exec returned 0 but image was not created")
        return False

    logger.info(f"Image {image_name} created successfully")
    return True


def run_claude(prompt: str, dry_run: bool, image_name: str) -> bool:
    claude_bin = shutil.which("claude")
    if not claude_bin:
        logger.error(
            "claude not found in PATH. Install the Claude Code extension or "
            "run: npm install -g @anthropic-ai/claude-code"
        )
        return False

    cmd = [
        claude_bin,
        "-p",
        "--model",
        CLAUDE_MODEL,
        "--dangerously-skip-permissions",
        "--no-session-persistence",
        "--output-format",
        "text",
    ]
    logger.info(f"Running claude: {claude_bin} -p --model {CLAUDE_MODEL} ...")
    if dry_run:
        logger.info("[dry-run] Prompt prepared in memory")
        logger.info("[dry-run] Would run claude; skipping.")
        return True

    # Explicitly set DeepSeek env vars for the subprocess so the harness is
    # self-contained and does not depend on the caller's environment.
    child_env = os.environ.copy()
    if CLAUDE_BASE_URL:
        child_env["ANTHROPIC_BASE_URL"] = CLAUDE_BASE_URL
    if CLAUDE_AUTH_TOKEN:
        child_env["ANTHROPIC_AUTH_TOKEN"] = CLAUDE_AUTH_TOKEN
    child_env["ANTHROPIC_MODEL"] = CLAUDE_MODEL

    import threading

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=child_env,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    proc.stdin.write(prompt)
    proc.stdin.close()

    def _stream() -> None:
        for line in proc.stdout:  # type: ignore[union-attr]
            stripped = line.rstrip()
            logger.info(stripped)
            print(stripped, flush=True)

    t = threading.Thread(target=_stream, daemon=True)
    t.start()
    t.join()
    proc.wait()

    if proc.returncode != 0:
        logger.error(f"claude -p exited with code {proc.returncode}")
        return False

    if not _image_exists(image_name):
        logger.error("claude -p returned 0 but image was not created")
        return False

    logger.info(f"Image {image_name} created successfully")
    return True


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────


def _resolve_extra_prompt(value: str) -> str:
    """Return prompt text from a literal string or a file path."""
    if not value:
        return ""
    if len(value) < 256:
        p = Path(value)
        if p.is_file():
            return p.read_text(encoding="utf-8")
    return value


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a Docker image for a benchmark repository using codex.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--repository",
        "-r",
        type=Path,
        required=False,
        metavar="PATH",
        help="Path to the repository to build (relative or absolute).",
    )
    parser.add_argument(
        "--host",
        action="store_true",
        help=(
            "Host-network mode: probe proxy on 127.0.0.1 and pass --network host to "
            "docker build so the container can reach the host proxy. "
            "Use this when the 172.x bridge gateway is blocked by the host firewall."
        ),
    )
    parser.add_argument(
        "--proxy",
        metavar="HOST:PORT",
        default="",
        help="Override proxy (e.g. 172.17.0.1:7890). Default: auto-detect.",
    )
    parser.add_argument(
        "--no-proxy",
        action="store_true",
        help="Disable proxy entirely.",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Skip all confirmation prompts.",
    )
    parser.add_argument(
        "--tools",
        metavar="TOOL,...",
        default="",
        help=f"Comma-separated optional tools to install in base image. Choices: {', '.join(ALL_TOOLS)}.",
    )
    parser.add_argument(
        "--rebuild-base",
        action="store_true",
        help="Force rebuild of base image even if it exists.",
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Force rebuild of repo image even if it exists.",
    )
    parser.add_argument(
        "--revision",
        metavar="REV",
        default="",
        help="Repository revision (commit hash or tag) to use in image tag. If not provided, auto-detect from git.",
    )
    parser.add_argument(
        "--config-show",
        action="store_true",
        help="Print current configuration and exit.",
    )
    parser.add_argument(
        "--proxy-map-template",
        action="store_true",
        help="Generate a template proxy_map.json for customization and exit.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate Dockerfile/prompt but do not build.",
    )
    parser.add_argument(
        "--extra-prompt",
        metavar="TEXT_OR_FILE",
        default="",
        help=(
            "Additional instructions appended to the codex prompt. "
            "Accepts a literal string or a path to a text file."
        ),
    )
    parser.add_argument(
        "--base-image",
        metavar="IMAGE",
        default="",
        help="Use this pre-built image as the base (skips base image build).",
    )
    parser.add_argument(
        "--harness",
        choices=["codex", "claude"],
        default="codex",
        help="Agent harness backend: 'codex' (gpt-5.4-mini, default) or 'claude' (deepseek-v4-flash).",
    )
    args = parser.parse_args()
    if not args.config_show and not args.proxy_map_template and args.repository is None:
        parser.error(
            "--repository is required unless --config-show or --proxy-map-template is given"
        )
    return args


def _get_repo_revision(repo_path: Path, explicit_revision: Optional[str] = None) -> Optional[str]:
    """Get repository revision (commit hash).

    Args:
        repo_path: Path to the repository
        explicit_revision: Explicit revision string provided by user

    Returns:
        Revision string (short commit hash) or None if not available
    """
    if explicit_revision:
        return explicit_revision

    # Try to get git commit hash
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            commit_hash = result.stdout.strip()
            if commit_hash:
                return commit_hash
    except Exception:  # noqa: BLE001
        pass

    return None


def _derive_image_name(slug: str, revision: Optional[str] = None) -> str:
    """Derive Docker image name from repository slug and optional revision.

    Args:
        slug: Repository slug (e.g., "apache__activemq")
        revision: Optional revision (commit hash or tag)

    Returns:
        Full image name with tag (e.g., "route-hacker-repo/apache__activemq:abc123" or ":latest")
    """
    slug = slug.lower()
    if revision:
        # Use revision as tag
        return f"{REPO_IMAGE_PREFIX}/{slug}:{revision}"
    else:
        # Fall back to :latest
        return f"{REPO_IMAGE_PREFIX}/{slug}:latest"


def _confirm(msg: str, headless: bool) -> bool:
    if headless:
        return True
    try:
        answer = input(f"{msg} [Y/n] ").strip().lower()
        return answer in ("", "y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def _handle_config_commands(args: argparse.Namespace, cfg: AppConfig) -> Optional[int]:
    """Handle --config-show and --proxy-map-template commands.

    Returns exit code if command was handled, None otherwise.
    """
    if args.config_show:
        show_config(cfg)
        return 0

    if args.proxy_map_template:
        template_path = save_proxy_map_template()
        print(f"[INFO] Proxy map template saved to: {template_path}")
        print(f"[INFO] Edit this file to customize proxy configurations for specific tools.")
        print(f"[INFO] Built-in defaults will be used for any tools not in the file.")
        return 0

    return None


def _initialize_config(args: argparse.Namespace, cfg: AppConfig) -> Optional[int]:
    """Initialize config file on first run.

    Returns exit code if user aborted, None otherwise.
    """
    config_path = _config_path()
    if not config_path.exists():
        _write_default_config(config_path)
        print(f"[INFO] Created default config at: {config_path}")
        print(f"[INFO] Cache dir: {_cache_dir()}")
        print(f"[INFO] Default tools: {', '.join(cfg.tools)}")
        if not _confirm("Proceed with these defaults?", args.headless):
            print("[INFO] Aborted. Edit the config file and re-run.")
            return 1
    return None


def _resolve_repository_path(args: argparse.Namespace) -> tuple[Optional[Path], Optional[int]]:
    """Resolve and validate repository path.

    Returns (repo_path, exit_code). If exit_code is not None, caller should return it.
    """
    repo_path = args.repository
    if not repo_path.is_absolute():
        repo_path = Path.cwd() / repo_path
    repo_path = repo_path.resolve()
    if not repo_path.is_dir():
        logger.error(f"Repository path does not exist or is not a directory: {repo_path}")
        return None, 2
    return repo_path, None


def _setup_build_logging(repo_path: Path) -> tuple[Path, str]:
    """Set up logging for the build.

    Returns (log_path, timestamp).
    """
    log_dir = _cache_dir() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")  # Add microseconds for uniqueness
    log_path = log_dir / f"{repo_path.name}_{timestamp}.log"
    setup_logging(log_path)
    return log_path, timestamp


def _resolve_build_tools(args: argparse.Namespace, cfg: AppConfig) -> list[str]:
    """Resolve which tools to include in the build."""
    tools = cfg.tools
    if args.tools:
        tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    return tools


def _compute_build_context(repo_path: Path) -> tuple[Optional[Path], Optional[str], Optional[int]]:
    """Compute Docker build context and repo copy path.

    Returns (build_context, repo_copy_path, exit_code).
    If exit_code is not None, caller should return it.
    """
    repo_path = repo_path.resolve()
    if not repo_path.is_dir():
        logger.error(f"Repository path does not exist or is not a directory: {repo_path}")
        return None, None, 2

    # Use the repository parent as context so repo paths restored outside the
    # route-hacker root are not filtered by the root .dockerignore.
    build_context = repo_path.parent
    repo_copy_path = repo_path.name
    return build_context, repo_copy_path, None


def _check_dockerfile_reuse(slug: str, revision: Optional[str], args: argparse.Namespace) -> bool:
    """Check if saved Dockerfile should be reused.

    Returns True if Dockerfile should be reused, False otherwise.
    Also copies the Dockerfile to tmp build dir if reusing.
    """
    saved_dockerfile = _saved_dockerfile_path(slug, revision)
    if not saved_dockerfile.exists():
        return False

    reuse_existing = False
    if args.headless:
        logger.info(f"Saved Dockerfile found at {saved_dockerfile}; headless mode → reusing it.")
        reuse_existing = True
    else:
        print(
            f"\n[INFO] A Dockerfile from a previous build was found:\n"
            f"       {saved_dockerfile}\n"
        )
        reuse_existing = _confirm(
            "Reuse this Dockerfile (try it first before re-inspecting)?", headless=False
        )
        if reuse_existing:
            logger.info("User chose to reuse saved Dockerfile.")
        else:
            logger.info("User chose to ignore saved Dockerfile; will re-inspect repo.")

    # If reusing, copy saved Dockerfile into the tmp build dir so codex can find it
    if reuse_existing:
        tmp_build_dir = _get_build_dir(slug)
        tmp_build_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(saved_dockerfile, tmp_build_dir / "Dockerfile")
        logger.info(f"Copied saved Dockerfile → {tmp_build_dir / 'Dockerfile'}")

    return reuse_existing


def _find_reference_dockerfiles(slug: str, revision: Optional[str], max_refs: int = 5) -> list[Path]:
    """Return up to max_refs cached Dockerfiles for this slug, excluding the current revision.

    All returned paths are from verified successful builds (only successes are saved).
    Sorted by mtime descending (most recently built first).
    """
    dockerfiles_dir = _cache_dir() / "dockerfiles" / slug
    if not dockerfiles_dir.is_dir():
        return []

    candidates = []
    for df in dockerfiles_dir.rglob("Dockerfile"):
        # Skip the exact-match revision (that's handled by _check_dockerfile_reuse)
        if revision and df.parent.name == revision:
            continue
        candidates.append(df)

    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[:max_refs]


def _save_dockerfile_if_exists(slug: str, revision: Optional[str]) -> None:
    """Save the generated Dockerfile to cache for future reuse."""
    src_df = _get_build_dir(slug) / "Dockerfile"
    if src_df.exists():
        dst_df = _saved_dockerfile_path(slug, revision)
        dst_df.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_df, dst_df)
        logger.info(f"Dockerfile saved to {dst_df}")


def _is_trivial_dockerfile(dockerfile_path: Path) -> bool:
    """Return True if the Dockerfile is simple enough that build notes add no value."""
    try:
        lines = [l for l in dockerfile_path.read_text(encoding="utf-8").splitlines() if l.strip() and not l.strip().startswith("#")]
        return len(lines) <= 5
    except OSError:
        return True


def _generate_build_notes(slug: str, revision: Optional[str], *, harness: str = "codex") -> None:
    """Ask the LLM to write a short build notes file alongside the saved Dockerfile.

    Only runs when the Dockerfile is non-trivial (> 5 non-comment lines).
    """
    dst_df = _saved_dockerfile_path(slug, revision)
    if not dst_df.exists():
        return
    if _is_trivial_dockerfile(dst_df):
        logger.info("Dockerfile is trivial; skipping build notes generation.")
        return

    notes_path = dst_df.parent / "build-notes.md"
    if notes_path.exists():
        logger.info(f"Build notes already exist at {notes_path}; skipping.")
        return

    try:
        import openai  # noqa: PLC0415
    except ImportError:
        logger.warning("openai package not available; skipping build notes generation.")
        return

    dockerfile_content = dst_df.read_text(encoding="utf-8")
    system_msg = (
        "You are a build engineer. Given a Dockerfile that successfully built a specific revision "
        "of a source repository, write a concise build notes file (2-5 sentences) explaining:\n"
        "1. What non-obvious steps were required (e.g. bootstrapping a parent POM, patching version strings)\n"
        "2. Why those steps were needed for this revision\n"
        "3. Any version-specific constraints to watch out for\n\n"
        "Output only the notes text in plain markdown. No headers, no code blocks, no preamble."
    )
    user_msg = (
        f"Repository: {slug}\n"
        f"Revision: {revision or 'unknown'}\n\n"
        f"Dockerfile:\n```dockerfile\n{dockerfile_content}\n```"
    )

    if harness == "claude":
        api_key = CLAUDE_AUTH_TOKEN
        base_url = CLAUDE_OPENAI_BASE_URL
        model = CLAUDE_MODEL
    else:
        api_key = os.environ.get("OPENAI_API_KEY", "")
        base_url = os.environ.get("OPENAI_BASE_URL") or None
        model = CODEX_MODEL

    try:
        client = openai.OpenAI(api_key=api_key, base_url=base_url)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg},
            ],
            max_tokens=300,
            temperature=0.2,
        )
        notes = (response.choices[0].message.content or "").strip()
        if notes:
            notes_path.write_text(notes + "\n", encoding="utf-8")
            logger.info(f"Build notes saved to {notes_path}")
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"Failed to generate build notes: {exc}")


def _ensure_codeql_db(image_name: str, repo_path: Path, *, timeout: int = 1800) -> bool:
    """Run CodeQL database creation inside a built image.

    Uses ``--build-mode=none`` which leverages pre-existing compilation
    artifacts — much faster than re-running the full build and doesn't depend
    on the LLM agent adding the step to the Dockerfile.

    Returns True if the CodeQL DB was created (or already existed).
    """
    # Fast check: does the image already have a CodeQL DB?
    check = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "", image_name,
         "test", "-d", "/codeql-db"],
        capture_output=True, text=True, timeout=30,
    )
    if check.returncode == 0:
        logger.info("CodeQL database already exists in %s; skipping.", image_name)
        return True

    logger.info("Creating CodeQL database for %s (build-mode=none) ...", image_name)
    cid = f"codeql-build-{uuid.uuid4().hex[:8]}"

    try:
        # Start a background container
        subprocess.run(
            ["docker", "run", "-d", "--name", cid, "--entrypoint", "sleep",
             image_name, "infinity"],
            check=True, capture_output=True, text=True, timeout=15,
        )
        # Create the CodeQL database from pre-existing compilation artifacts
        cmd = (
            "cd /workspace/repo && "
            "/usr/local/bin/codeql database create /codeql-db "
            "--language=java-kotlin "
            "--source-root=. "
            "--build-mode=none "
            "--overwrite"
        )
        result = subprocess.run(
            ["docker", "exec", cid, "bash", "-c", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0:
            subprocess.run(
                ["docker", "commit", cid, image_name],
                check=True, capture_output=True, text=True, timeout=60,
            )
            logger.info("CodeQL database created and committed for %s.", image_name)
            return True
        else:
            tail = result.stderr[-400:] if result.stderr else result.stdout[-400:]
            logger.warning("CodeQL database creation failed for %s: %s", image_name, tail)
            return False
    except subprocess.TimeoutExpired:
        logger.warning("CodeQL database creation timed out for %s after %ds.", image_name, timeout)
        return False
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, timeout=10)


def main() -> int:
    args = _parse_args()
    cfg = load_config()

    # Handle config-related commands
    exit_code = _handle_config_commands(args, cfg)
    if exit_code is not None:
        return exit_code

    # Initialize config on first run
    exit_code = _initialize_config(args, cfg)
    if exit_code is not None:
        return exit_code

    # Resolve and validate repository path
    repo_path, exit_code = _resolve_repository_path(args)
    if exit_code is not None:
        return exit_code

    # Set up logging
    log_path, timestamp = _setup_build_logging(repo_path)
    print(f"[INFO] Log file: {log_path}", flush=True)
    logger.info(f"Repository  : {repo_path}")
    logger.info(f"Log file    : {log_path}")

    # Resolve tools
    tools = _resolve_build_tools(args, cfg)
    logger.info(f"Tools       : {', '.join(tools) or '(none)'}")

    # Proxy detection
    proxy = detect_proxy(cfg, override=args.proxy, no_proxy=args.no_proxy, host_mode=args.host)
    if proxy:
        logger.info(f"Proxy       : {proxy.url}")
    else:
        logger.info("Proxy       : none detected")
    logger.info(f"Network mode: {'host (--host)' if args.host else 'bridge (default)'}")
    model_name = CODEX_MODEL if args.harness == "codex" else CLAUDE_MODEL
    logger.info(f"Harness     : {args.harness} ({model_name})")

    # Build system detection — use codex for codex harness, fallback for claude
    if args.harness == "claude":
        build_systems = _detect_build_system_fallback(repo_path)
    else:
        build_systems = detect_build_system(repo_path, dry_run=args.dry_run)
    logger.info(f"Build system: {', '.join(build_systems) or 'unknown'}")

    # Get repository revision
    slug = repo_path.name
    revision = _get_repo_revision(repo_path, args.revision if args.revision else None)
    if revision:
        logger.info(f"Revision    : {revision}")
    else:
        logger.info("Revision    : none (using :latest tag)")

    # Derive image name
    image_name = _derive_image_name(slug, revision)
    logger.info(f"Image       : {image_name}")

    # Compute build context
    build_context, repo_copy_path, exit_code = _compute_build_context(repo_path)
    if exit_code is not None:
        return exit_code

    logger.info(f"Build context: {build_context}")
    logger.info(f"Docker COPY  : {repo_copy_path}")
    docker_build_network_flag = "--network host" if _needs_host_network(proxy, args.host) else ""
    logger.info(f"Docker net   : {docker_build_network_flag or '(default bridge)'}")

    # Build or reuse base image
    if args.base_image:
        base_image_full = args.base_image
        logger.info(f"Using provided base image: {base_image_full}")
    else:
        ok, base_image_full = build_base_image(
            proxy=proxy,
            tools=tools,
            base_image_prefix=cfg.base_image,
            rebuild=args.rebuild_base,
            dry_run=args.dry_run,
            host_mode=args.host,
        )
        if not ok:
            return 3
        logger.info(f"Using base image: {base_image_full}")

    # Check if repo image already exists (skip if --rebuild is set)
    if not args.rebuild and _image_exists(image_name):
        logger.info(f"Image {image_name} already exists; skipping build (use --rebuild to force).")
        logger.info(f"Done. Image: {image_name}")
        return 0

    # No-compile mode: empty repo or .no-compile marker → skip agent, build trivial image
    if _is_no_compile_repo(repo_path):
        logger.info("No-compile repo detected; skipping agent, building trivial image.")
        ok = build_trivial_repo_image(
            repo_path=repo_path,
            image_name=image_name,
            base_image=base_image_full,
            dry_run=args.dry_run,
            host_mode=args.host,
        )
        if ok:
            logger.info(f"Done. Image: {image_name}")
            return 0
        else:
            logger.error(f"Build failed. See log: {log_path}")
            return 4

    # Check if saved Dockerfile should be reused
    reuse_existing = _check_dockerfile_reuse(slug, revision, args)

    # If no exact-match Dockerfile, look for one from a nearby revision as a hint
    ref_dockerfiles: list[Path] = []
    if not reuse_existing:
        ref_dockerfiles = _find_reference_dockerfiles(slug, revision)
        if ref_dockerfiles:
            logger.info(f"Found {len(ref_dockerfiles)} reference Dockerfile(s) for hint.")

    # Get unique build directory for this process
    build_dir = _get_build_dir(slug)
    build_cache_dir = _repo_build_cache_dir(slug)

    # Stage per-repo build assets from platformdirs into the Docker build context
    staged_assets_dir = _stage_build_assets(slug)
    if staged_assets_dir:
        logger.info(f"Build assets staged at: {staged_assets_dir}")
    else:
        logger.info(f"No build assets found in {_data_dir() / 'build-assets' / slug}; skipping staging.")

    docker_run_network_flag = "--network host" if docker_build_network_flag else ""
    container_name = _prepare_debug_container(
        repo_path=repo_path,
        slug=slug,
        base_image=base_image_full,
        docker_run_network_flag=docker_run_network_flag,
        build_cache_dir=build_cache_dir,
        dry_run=args.dry_run,
    )

    # Generate codex prompt
    # Deadline = now + half of outer timeout (10800s / 2 = 5400s).
    # After this point codex should stop issuing new commands and only verify.
    deadline_unix = int(datetime.now().timestamp()) + 5400
    extra_prompt = _resolve_extra_prompt(args.extra_prompt)
    prompt = _build_codex_prompt(
        repo_path=repo_path,
        build_context=build_context,
        repo_copy_path=repo_copy_path,
        docker_build_network_flag=docker_build_network_flag,
        build_systems=build_systems,
        image_name=image_name,
        base_image=base_image_full,
        proxy=proxy,
        tools=tools,
        build_dir=build_dir,
        existing_dockerfile=reuse_existing,
        reference_dockerfiles=ref_dockerfiles,
        deadline_unix=deadline_unix,
        extra_prompt=extra_prompt,
        staged_assets_dir=staged_assets_dir,
        build_cache_dir=build_cache_dir,
        container_name=container_name,
    )

    # Write prompt to cache for inspection
    prompt_cache = _cache_dir() / "prompts" / f"{slug}_{timestamp}.txt"
    prompt_cache.parent.mkdir(parents=True, exist_ok=True)
    prompt_cache.write_text(prompt, encoding="utf-8")
    logger.info(f"Agent prompt: {prompt_cache}")

    # Run agent (codex or claude)
    harness_label = args.harness
    image_id_before = _image_id(image_name)
    if args.harness == "claude":
        ok = run_claude(prompt=prompt, dry_run=args.dry_run, image_name=image_name)
    else:
        ok = run_codex(prompt=prompt, dry_run=args.dry_run, image_name=image_name)

    if args.dry_run:
        if ok:
            logger.info(f"[dry-run] Prompt generated. Target image would be: {image_name}")
            return 0
        logger.error(f"[dry-run] Prompt generation failed. See log: {log_path}")
        return 4

    if ok and _image_exists(image_name):
        _save_dockerfile_if_exists(slug, revision)
        _generate_build_notes(slug, revision, harness=args.harness)
        if "codeql" in tools:
            _ensure_codeql_db(image_name, repo_path)
        logger.info(f"Done. Image: {image_name}")
        return 0
    else:
        # Check if image was actually created despite agent reporting failure
        image_id_after = _image_id(image_name)
        if not ok and image_id_after and image_id_after != image_id_before:
            logger.warning(
                f"{harness_label} reported failure, but image was produced successfully; treating as success"
            )
            _save_dockerfile_if_exists(slug, revision)
            _generate_build_notes(slug, revision, harness=args.harness)
            if "codeql" in tools:
                _ensure_codeql_db(image_name, repo_path)
            logger.info(f"Done. Image: {image_name}")
            return 0
        if ok:
            logger.error(f"Build marker found but image is missing after {harness_label} run")
        logger.error(f"Build failed. See log: {log_path}")
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
