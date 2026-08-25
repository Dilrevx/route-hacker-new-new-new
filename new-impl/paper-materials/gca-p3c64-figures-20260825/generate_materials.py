#!/usr/bin/env python3
"""Generate paper-facing GCA and P3C64 material from existing artifacts.

The script intentionally uses only the Python standard library so it can run on
the local macOS environment where plotting packages may be unavailable.
"""

from __future__ import annotations

import html
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median


REPO_ROOT = Path("/Users/bytedance/workspace/route-hacker-new-new-main-new-guideline")
RESULT_ROOT = REPO_ROOT / "new-impl/new-guideline/results"
OUT_DIR = REPO_ROOT / "new-impl/paper-materials/gca-p3c64-figures-20260825"

COVERAGE_SUMMARY = RESULT_ROOT / "guideline-v2-coverage-audit-full143-20260824/summary.json"
CASE_COVERAGE = RESULT_ROOT / "guideline-v2-coverage-audit-full143-20260824/case_coverage.jsonl"
GUIDELINE_OVERRIDES = (
    RESULT_ROOT
    / "mechanism-guideline-preview-v2-cluster-scope-r8-release-ready-20260823/guideline_overrides.jsonl"
)
MECHANISM_CANDIDATES = (
    RESULT_ROOT
    / "mechanism-guideline-preview-v2-cluster-scope-r8-release-ready-20260823/mechanism_candidates.jsonl"
)
P3C64_SUMMARY = RESULT_ROOT / "p3c64-fixed143-paper-eval-20260820/summary.json"
P3C64_RANKS = RESULT_ROOT / "p3c64-fixed143-paper-eval-20260820/p3c64_case_rank_table.jsonl"
QWEN4B_RANKS = RESULT_ROOT / "p3c64-fixed143-paper-eval-20260820/qwen4b_case_rank_table.jsonl"
QWEN4B_COMPARISON = RESULT_ROOT / "p3c64-fixed143-paper-eval-20260820/qwen4b_comparison.json"
QWEN4B_METRICS = RESULT_ROOT / "model_ablation_qwen4b_full143/qwen3_embedding_4b/metrics.json"
STRUCTURED_CVES = Path("/tmp/hcvr_guideline_coverage_audit_20260824/structured_cves_combined.jsonl")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def xml_escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def pct(n: float, d: float) -> str:
    if not d:
        return "0.0%"
    return f"{100.0 * n / d:.1f}%"


def short_identity(identity: str) -> str:
    return identity.replace("__", "/").replace("::", " ")


def bar_svg(
    title: str,
    subtitle: str,
    rows: list[tuple[str, float, str]],
    path: Path,
    width: int = 980,
    row_h: int = 34,
    left: int = 310,
    right: int = 120,
) -> None:
    max_value = max((v for _, v, _ in rows), default=1)
    height = 92 + row_h * len(rows) + 36
    chart_w = width - left - right
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<style><![CDATA[',
        "text{font-family:Arial,Helvetica,sans-serif;fill:#17202a} .title{font-size:24px;font-weight:700}",
        ".sub{font-size:13px;fill:#5d6d7e}.label{font-size:13px}.value{font-size:13px;font-weight:700}",
        ".axis{stroke:#d6dbdf;stroke-width:1}.bar{fill:#2878b5}.bar2{fill:#d1495b}.bg{fill:#f7f9fb}",
        "]]></style>",
        f'<rect width="{width}" height="{height}" fill="white"/>',
        f'<text class="title" x="28" y="34">{xml_escape(title)}</text>',
        f'<text class="sub" x="28" y="58">{xml_escape(subtitle)}</text>',
        f'<line class="axis" x1="{left}" y1="78" x2="{left + chart_w}" y2="78"/>',
    ]
    y = 92
    for i, (label, value, note) in enumerate(rows):
        bw = 0 if max_value <= 0 else chart_w * value / max_value
        fill = "#2878b5" if i % 2 == 0 else "#3c9d8f"
        parts.extend(
            [
                f'<text class="label" x="28" y="{y + 19}">{xml_escape(label)}</text>',
                f'<rect class="bg" x="{left}" y="{y}" width="{chart_w}" height="22" rx="3"/>',
                f'<rect x="{left}" y="{y}" width="{bw:.1f}" height="22" rx="3" fill="{fill}"/>',
                f'<text class="value" x="{left + bw + 8:.1f}" y="{y + 16}">{xml_escape(note)}</text>',
            ]
        )
        y += row_h
    parts.append("</svg>")
    write(path, "\n".join(parts))


def grouped_hit_svg(
    comparison: dict,
    path: Path,
    width: int = 980,
    height: int = 520,
) -> None:
    budgets = [30, 50, 100, 200, 300, 500]
    metrics = comparison["metrics_on_common_identities"]
    left = [metrics[f"hit_at_{k}"]["left_count"] for k in budgets]
    right = [metrics[f"hit_at_{k}"]["right_count"] for k in budgets]
    deltas = [metrics[f"hit_at_{k}"]["delta_count"] for k in budgets]
    max_y = 143
    margin_l, margin_r, margin_t, margin_b = 70, 34, 74, 72
    chart_w = width - margin_l - margin_r
    chart_h = height - margin_t - margin_b
    group_w = chart_w / len(budgets)
    bar_w = group_w * 0.28

    def y(value: float) -> float:
        return margin_t + chart_h * (1 - value / max_y)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<style><![CDATA[',
        "text{font-family:Arial,Helvetica,sans-serif;fill:#17202a}.title{font-size:24px;font-weight:700}",
        ".sub{font-size:13px;fill:#5d6d7e}.axis{stroke:#d6dbdf;stroke-width:1}.tick{font-size:12px;fill:#6c7a89}",
        ".label{font-size:13px}.num{font-size:12px;font-weight:700}.p3{fill:#2878b5}.qw{fill:#d1495b}.delta{fill:#1f8f72}",
        "]]></style>",
        f'<rect width="{width}" height="{height}" fill="white"/>',
        '<text class="title" x="28" y="34">P3C64 improves known-anchor retrieval under the same 143 identities</text>',
        '<text class="sub" x="28" y="58">Bars show hit counts at each audit budget. Labels above groups are P3C64 minus Qwen3-Embedding-4B.</text>',
    ]
    for t in [0, 30, 60, 90, 120, 143]:
        yy = y(t)
        parts.append(f'<line class="axis" x1="{margin_l}" y1="{yy:.1f}" x2="{width - margin_r}" y2="{yy:.1f}"/>')
        parts.append(f'<text class="tick" x="28" y="{yy + 4:.1f}">{t}</text>')
    parts.append(f'<line class="axis" x1="{margin_l}" y1="{margin_t}" x2="{margin_l}" y2="{margin_t + chart_h}"/>')
    parts.append(f'<line class="axis" x1="{margin_l}" y1="{margin_t + chart_h}" x2="{width - margin_r}" y2="{margin_t + chart_h}"/>')
    for i, k in enumerate(budgets):
        gx = margin_l + i * group_w + group_w * 0.18
        y_left = y(left[i])
        y_right = y(right[i])
        parts.extend(
            [
                f'<rect class="p3" x="{gx:.1f}" y="{y_left:.1f}" width="{bar_w:.1f}" height="{margin_t + chart_h - y_left:.1f}" rx="3"/>',
                f'<rect class="qw" x="{gx + bar_w + 8:.1f}" y="{y_right:.1f}" width="{bar_w:.1f}" height="{margin_t + chart_h - y_right:.1f}" rx="3"/>',
                f'<text class="num" x="{gx + 2:.1f}" y="{y_left - 7:.1f}">{left[i]}</text>',
                f'<text class="num" x="{gx + bar_w + 10:.1f}" y="{y_right - 7:.1f}">{right[i]}</text>',
                f'<text class="delta" x="{gx + 6:.1f}" y="{margin_t + chart_h + 42:.1f}">+{deltas[i]}</text>',
                f'<text class="label" x="{gx + 5:.1f}" y="{margin_t + chart_h + 22:.1f}">Top {k}</text>',
            ]
        )
    lx = width - 325
    parts.extend(
        [
            f'<rect class="p3" x="{lx}" y="22" width="14" height="14" rx="2"/>',
            f'<text class="label" x="{lx + 20}" y="34">P3C64</text>',
            f'<rect class="qw" x="{lx + 96}" y="22" width="14" height="14" rx="2"/>',
            f'<text class="label" x="{lx + 116}" y="34">Qwen3-Embedding-4B</text>',
        ]
    )
    parts.append("</svg>")
    write(path, "\n".join(parts))


def gca_space_contrast_svg(
    summary: dict,
    cwe_rows: list[tuple[str, int, Counter]],
    mechanism_rows: list[tuple[str, int, Counter]],
    path: Path,
    width: int = 1120,
    height: int = 650,
) -> None:
    total = summary["identity_count"]
    metadata = summary["metadata_presence"]
    upper = summary["coverage_upper_bounds"]
    cwe_focus = cwe_rows[:4]
    mech_focus = [
        row
        for row in mechanism_rows
        if row[0]
        in {
            "mech_jndi_untrusted_lookup_target",
            "mech_ssrf_webhook_url_fetch",
            "mech_path_traversal_missing_canonical_prefix",
            "mech_open_redirect_unsafe_uri_scheme",
        }
    ][:4]
    if len(mech_focus) < 4:
        mech_focus = mechanism_rows[:4]

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<style><![CDATA[",
        "text{font-family:Arial,Helvetica,sans-serif;fill:#17202a}.title{font-size:24px;font-weight:700}",
        ".sub{font-size:13px;fill:#5d6d7e}.h{font-size:16px;font-weight:700}.label{font-size:13px}.small{font-size:12px;fill:#5d6d7e}",
        ".box{fill:#f7f9fb;stroke:#d6dbdf;stroke-width:1}.cwe{fill:#d1495b}.gca{fill:#2878b5}.good{fill:#1f8f72}.line{stroke:#b0bec5;stroke-width:1.5;opacity:.72}",
        "]]></style>",
        f'<rect width="{width}" height="{height}" fill="white"/>',
        '<text class="title" x="28" y="36">GCA mechanism space resolves part of CVE/CWE metadata noise</text>',
        '<text class="sub" x="28" y="60">The 143-case paper set has sparse/incomplete CWE metadata, while GCA produces mechanism-level audit obligations with explicit release headroom.</text>',
    ]

    # Panel 1: metadata availability.
    x0, y0 = 28, 92
    parts.append(f'<rect class="box" x="{x0}" y="{y0}" width="330" height="500" rx="6"/>')
    parts.append(f'<text class="h" x="{x0 + 18}" y="{y0 + 32}">CVE/CWE annotation space</text>')
    meta_rows = [
        ("Dataset CWE present", metadata.get("dataset_cwe_present", 0), "#d1495b"),
        ("Structured CWE joined", metadata.get("structured_cwe_present", 0), "#e58f65"),
        ("CVE IDs ingested upper bound", upper.get("if_all_cve_ids_ingested", 0), "#1f8f72"),
    ]
    bar_x, bar_y, bar_w = x0 + 30, y0 + 68, 250
    for i, (label, value, color) in enumerate(meta_rows):
        yy = bar_y + i * 58
        bw = bar_w * value / total
        parts.append(f'<text class="label" x="{bar_x}" y="{yy - 8}">{xml_escape(label)}</text>')
        parts.append(f'<rect x="{bar_x}" y="{yy}" width="{bar_w}" height="18" fill="#eef2f5" rx="3"/>')
        parts.append(f'<rect x="{bar_x}" y="{yy}" width="{bw:.1f}" height="18" fill="{color}" rx="3"/>')
        parts.append(f'<text class="small" x="{bar_x + bar_w + 10}" y="{yy + 14}">{value}/{total}</text>')
    parts.append(f'<text class="small" x="{x0 + 18}" y="{y0 + 268}">Top CWE labels by mechanism fan-out:</text>')
    yy = y0 + 302
    for cwe, n, mechanisms in cwe_focus:
        parts.append(f'<circle cx="{x0 + 34}" cy="{yy - 4}" r="{max(5, min(20, n))}" class="cwe" opacity=".85"/>')
        parts.append(f'<text class="label" x="{x0 + 66}" y="{yy}">{xml_escape(cwe)} -> {n} GCA mechanisms</text>')
        top = ", ".join(m for m, _ in mechanisms.most_common(2))
        parts.append(f'<text class="small" x="{x0 + 66}" y="{yy + 18}">{xml_escape(top[:52])}</text>')
        yy += 52

    # Panel 2: GCA mechanism space.
    x1 = 390
    parts.append(f'<rect class="box" x="{x1}" y="{y0}" width="330" height="500" rx="6"/>')
    parts.append(f'<text class="h" x="{x1 + 18}" y="{y0 + 32}">GCA mechanism space</text>')
    gca_rows = [
        ("Released primary sidecar", upper.get("current_primary_sidecar", 0), "#2878b5"),
        ("With review queue release", upper.get("if_review_queue_released_for_current_candidates", 0), "#3c9d8f"),
        ("With raw/noise release", upper.get("if_noise_singletons_released_from_current_raw_structured", 0), "#1f8f72"),
    ]
    for i, (label, value, color) in enumerate(gca_rows):
        yy = bar_y + i * 58
        bw = bar_w * value / total
        parts.append(f'<text class="label" x="{x1 + 30}" y="{yy - 8}">{xml_escape(label)}</text>')
        parts.append(f'<rect x="{x1 + 30}" y="{yy}" width="{bar_w}" height="18" fill="#eef2f5" rx="3"/>')
        parts.append(f'<rect x="{x1 + 30}" y="{yy}" width="{bw:.1f}" height="18" fill="{color}" rx="3"/>')
        parts.append(f'<text class="small" x="{x1 + 30 + bar_w + 10}" y="{yy + 14}">{value}/{total}</text>')
    parts.append(f'<text class="small" x="{x1 + 18}" y="{y0 + 268}">Reusable mechanisms crossing CWE labels:</text>')
    yy = y0 + 302
    for mech, n, cwes in mech_focus:
        parts.append(f'<circle cx="{x1 + 34}" cy="{yy - 4}" r="{max(5, min(22, n / 2))}" class="gca" opacity=".88"/>')
        short = mech.replace("mech_", "")
        if len(short) > 38:
            short = short[:35] + "..."
        parts.append(f'<text class="label" x="{x1 + 66}" y="{yy}">{xml_escape(short)} -> {n} CWE labels</text>')
        top = ", ".join(f"{c}({v})" for c, v in cwes.most_common(3))
        parts.append(f'<text class="small" x="{x1 + 66}" y="{yy + 18}">{xml_escape(top[:55])}</text>')
        yy += 52

    # Panel 3: concrete JNDI fan-in/fan-out.
    x2 = 752
    parts.append(f'<rect class="box" x="{x2}" y="{y0}" width="340" height="500" rx="6"/>')
    parts.append(f'<text class="h" x="{x2 + 18}" y="{y0 + 32}">Example: JNDI guideline</text>')
    cx, cy = x2 + 170, y0 + 210
    parts.append(f'<circle cx="{cx}" cy="{cy}" r="62" fill="#2878b5" opacity=".92"/>')
    parts.append(f'<text x="{cx - 54}" y="{cy - 6}" fill="white" font-size="14" font-weight="700">attacker-controlled</text>')
    parts.append(f'<text x="{cx - 42}" y="{cy + 14}" fill="white" font-size="14" font-weight="700">JNDI lookup</text>')
    jndi_cwes = ["CWE-502", "CWE-20", "CWE-184", "CWE-74", "CWE-918", "CWE-99", "CWE-470"]
    positions = [
        (x2 + 56, y0 + 92),
        (x2 + 210, y0 + 92),
        (x2 + 52, y0 + 150),
        (x2 + 250, y0 + 157),
        (x2 + 48, y0 + 305),
        (x2 + 220, y0 + 317),
        (x2 + 125, y0 + 382),
    ]
    for cwe, (xx, yy) in zip(jndi_cwes, positions):
        parts.append(f'<line class="line" x1="{cx}" y1="{cy}" x2="{xx + 30}" y2="{yy - 4}"/>')
        parts.append(f'<rect x="{xx}" y="{yy - 22}" width="86" height="28" rx="4" fill="#fdecea" stroke="#f2b8b5"/>')
        parts.append(f'<text class="small" x="{xx + 12}" y="{yy - 4}">{cwe}</text>')
    parts.append(f'<text class="small" x="{x2 + 28}" y="{y0 + 448}">One mechanism, multiple noisy labels and clusters.</text>')
    parts.append(f'<text class="small" x="{x2 + 28}" y="{y0 + 468}">This is the paper-friendly data-quality story.</text>')
    parts.append("</svg>")
    write(path, "\n".join(parts))


def p3c64_by_type_svg(joined: list[dict], path: Path, width: int = 1080, height: int = 600) -> None:
    by_type: dict[str, list[dict]] = defaultdict(list)
    for row in joined:
        by_type[row.get("hcvr_type") or "unknown"].append(row)
    rows = []
    for typ, items in by_type.items():
        if len(items) < 3:
            continue
        p3_100 = sum(1 for d in items if d["p3_rank"] <= 100)
        q4_100 = sum(1 for d in items if d["qwen_rank"] <= 100)
        p3_200 = sum(1 for d in items if d["p3_rank"] <= 200)
        q4_200 = sum(1 for d in items if d["qwen_rank"] <= 200)
        rows.append((typ, len(items), p3_100, q4_100, p3_200, q4_200))
    rows.sort(key=lambda r: ((r[2] - r[3]) + (r[4] - r[5]), r[1]), reverse=True)
    rows = rows[:10]
    margin_l, margin_r, margin_t, margin_b = 330, 54, 78, 56
    row_h = 43
    height = max(height, margin_t + margin_b + row_h * len(rows))
    chart_w = width - margin_l - margin_r
    max_n = max((r[1] for r in rows), default=1)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<style><![CDATA[",
        "text{font-family:Arial,Helvetica,sans-serif;fill:#17202a}.title{font-size:24px;font-weight:700}",
        ".sub{font-size:13px;fill:#5d6d7e}.label{font-size:13px}.small{font-size:12px;fill:#5d6d7e}.axis{stroke:#d6dbdf;stroke-width:1}",
        ".p3{fill:#2878b5}.qw{fill:#d1495b}.bg{fill:#eef2f5}.delta{fill:#1f8f72;font-weight:700}",
        "]]></style>",
        f'<rect width="{width}" height="{height}" fill="white"/>',
        '<text class="title" x="28" y="34">P3C64 gains concentrate on mechanism-level retrieval families</text>',
        '<text class="sub" x="28" y="58">Per-type Hit@100 counts on the same 143 identities; rows with at least three cases are shown.</text>',
    ]
    y0 = margin_t
    for i, (typ, n, p3_100, q4_100, p3_200, q4_200) in enumerate(rows):
        yy = y0 + i * row_h
        label = typ if len(typ) <= 38 else typ[:35] + "..."
        parts.append(f'<text class="label" x="28" y="{yy + 18}">{xml_escape(label)}</text>')
        parts.append(f'<text class="small" x="240" y="{yy + 18}">n={n}</text>')
        parts.append(f'<rect class="bg" x="{margin_l}" y="{yy}" width="{chart_w}" height="14" rx="3"/>')
        p3w = chart_w * p3_100 / max_n
        q4w = chart_w * q4_100 / max_n
        parts.append(f'<rect class="p3" x="{margin_l}" y="{yy}" width="{p3w:.1f}" height="14" rx="3"/>')
        parts.append(f'<rect class="qw" x="{margin_l}" y="{yy + 18}" width="{q4w:.1f}" height="14" rx="3"/>')
        parts.append(f'<text class="small" x="{margin_l + max(p3w, q4w) + 10:.1f}" y="{yy + 14}">Top100: {p3_100} vs {q4_100}</text>')
        parts.append(f'<text class="delta" x="{width - margin_r - 82}" y="{yy + 28}">Top200 +{p3_200 - q4_200}</text>')
    parts.append(f'<rect class="p3" x="760" y="24" width="14" height="14" rx="2"/><text class="label" x="780" y="36">P3C64 Top100</text>')
    parts.append(f'<rect class="qw" x="900" y="24" width="14" height="14" rx="2"/><text class="label" x="920" y="36">Qwen4B Top100</text>')
    parts.append("</svg>")
    write(path, "\n".join(parts))


def rank_shift_svg(
    joined: list[dict],
    path: Path,
    width: int = 980,
    height: int = 650,
) -> None:
    improved = [d for d in joined if d["p3_rank"] < d["qwen_rank"]]
    worsened = [d for d in joined if d["p3_rank"] > d["qwen_rank"]]
    same = [d for d in joined if d["p3_rank"] == d["qwen_rank"]]
    left_only_200 = [d for d in joined if d["p3_rank"] <= 200 < d["qwen_rank"]]
    right_only_200 = [d for d in joined if d["qwen_rank"] <= 200 < d["p3_rank"]]
    left_only_100 = [d for d in joined if d["p3_rank"] <= 100 < d["qwen_rank"]]

    # Draw the most illustrative rank shifts on a log-scale slope chart.
    picks = sorted(left_only_200, key=lambda d: (d["p3_rank"], -d["qwen_rank"]))[:10]
    if len(picks) < 10:
        picks.extend(sorted(left_only_100, key=lambda d: (d["p3_rank"], -d["qwen_rank"]))[: 10 - len(picks)])
    seen = set()
    unique_picks = []
    for d in picks:
        if d["identity_key"] not in seen:
            unique_picks.append(d)
            seen.add(d["identity_key"])
    picks = unique_picks[:10]

    def y(rank: int) -> float:
        rank = max(1, min(rank, 10000))
        lo, hi = math.log10(1), math.log10(10000)
        return 110 + (math.log10(rank) - lo) / (hi - lo) * 430

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<style><![CDATA[',
        "text{font-family:Arial,Helvetica,sans-serif;fill:#17202a}.title{font-size:24px;font-weight:700}",
        ".sub{font-size:13px;fill:#5d6d7e}.axis{stroke:#d6dbdf;stroke-width:1}.guide{stroke:#eef2f5;stroke-width:1}",
        ".line{stroke:#2878b5;stroke-width:2;fill:none}.dot{fill:#2878b5}.small{font-size:12px}.label{font-size:13px}.metric{font-size:18px;font-weight:700}.box{fill:#f7f9fb;stroke:#d6dbdf}",
        "]]></style>",
        f'<rect width="{width}" height="{height}" fill="white"/>',
        '<text class="title" x="28" y="34">Representative rank shifts after P3C64 fine-tuning</text>',
        '<text class="sub" x="28" y="58">Lower rank is better. Lines show cases that enter Top-200 with P3C64 but not Qwen3-Embedding-4B.</text>',
    ]
    x_q, x_p = 220, 500
    for tick in [1, 10, 100, 1000, 10000]:
        yy = y(tick)
        parts.append(f'<line class="guide" x1="160" y1="{yy:.1f}" x2="620" y2="{yy:.1f}"/>')
        parts.append(f'<text class="small" x="106" y="{yy + 4:.1f}">{tick}</text>')
    parts.extend(
        [
            f'<line class="axis" x1="{x_q}" y1="100" x2="{x_q}" y2="550"/>',
            f'<line class="axis" x1="{x_p}" y1="100" x2="{x_p}" y2="550"/>',
            f'<text class="label" x="{x_q - 62}" y="88">Qwen4B rank</text>',
            f'<text class="label" x="{x_p - 42}" y="88">P3C64 rank</text>',
        ]
    )
    for idx, d in enumerate(picks):
        yq, yp = y(d["qwen_rank"]), y(d["p3_rank"])
        color = "#2878b5" if idx % 2 == 0 else "#1f8f72"
        label = short_identity(d["identity_key"])
        if len(label) > 56:
            label = label[:53] + "..."
        parts.extend(
            [
                f'<line x1="{x_q}" y1="{yq:.1f}" x2="{x_p}" y2="{yp:.1f}" stroke="{color}" stroke-width="2" opacity="0.85"/>',
                f'<circle cx="{x_q}" cy="{yq:.1f}" r="4" fill="{color}"/>',
                f'<circle cx="{x_p}" cy="{yp:.1f}" r="4" fill="{color}"/>',
                f'<text class="small" x="{x_p + 18}" y="{yp + 4:.1f}">{xml_escape(label)} ({d["qwen_rank"]} -> {d["p3_rank"]})</text>',
            ]
        )
    stats_x = 675
    stats = [
        ("Improved ranks", len(improved)),
        ("Worsened ranks", len(worsened)),
        ("Unchanged ranks", len(same)),
        ("P3C64-only Top-200", len(left_only_200)),
        ("Qwen4B-only Top-200", len(right_only_200)),
    ]
    parts.append(f'<rect class="box" x="{stats_x}" y="104" width="270" height="176" rx="6"/>')
    yy = 138
    for label, value in stats:
        parts.append(f'<text class="metric" x="{stats_x + 20}" y="{yy}">{value}</text>')
        parts.append(f'<text class="label" x="{stats_x + 78}" y="{yy}">{xml_escape(label)}</text>')
        yy += 31
    parts.append('<text class="sub" x="675" y="318">Interpretation: this supports improved</text>')
    parts.append('<text class="sub" x="675" y="338">mechanism-conditioned ranking, not a</text>')
    parts.append('<text class="sub" x="675" y="358">standalone proof of semantic geometry.</text>')
    parts.append("</svg>")
    write(path, "\n".join(parts))


def load_cve_to_cwes() -> dict[str, list[str]]:
    cve_to_cwes: dict[str, list[str]] = {}
    for row in read_jsonl(STRUCTURED_CVES):
        cwes = row.get("cwe_chain") or []
        if cwes:
            cve_to_cwes[row["cve_id"]] = list(dict.fromkeys(cwes))
    return cve_to_cwes


def build_mechanism_cwe_stats() -> tuple[list[dict], dict[str, Counter], dict[str, Counter]]:
    cve_to_cwes = load_cve_to_cwes()
    candidates = read_jsonl(MECHANISM_CANDIDATES)
    mechanism_to_cwes: dict[str, Counter] = defaultdict(Counter)
    cwe_to_mechanisms: dict[str, Counter] = defaultdict(Counter)
    rows = []
    for cand in candidates:
        mech = cand.get("mechanism_id")
        if not mech or mech.startswith("pending_"):
            continue
        for cve in cand.get("members") or []:
            for cwe in cve_to_cwes.get(cve, []):
                mechanism_to_cwes[mech][cwe] += 1
                cwe_to_mechanisms[cwe][mech] += 1
        rows.append(cand)
    return rows, mechanism_to_cwes, cwe_to_mechanisms


def generate_guideline_case() -> dict:
    overrides = read_jsonl(GUIDELINE_OVERRIDES)
    jndi = next(
        row
        for row in overrides
        if row.get("identity_key") == "apache__axis-axis1-java::CVE-2023-51441"
        and "mech_jndi_untrusted_lookup_target" in row.get("mechanism_ids", [])
    )
    candidates = read_jsonl(MECHANISM_CANDIDATES)
    jndi_candidates = [
        row for row in candidates if row.get("mechanism_id") == "mech_jndi_untrusted_lookup_target"
    ]
    cluster_ids = sorted({row.get("cluster_id") for row in jndi_candidates})
    all_members = sorted({cve for row in jndi_candidates for cve in row.get("members", [])})
    matched_terms = sorted({term for row in jndi_candidates for term in row.get("matched_terms", [])})
    cve_to_cwes = load_cve_to_cwes()
    cwe_counts = Counter()
    for cve in all_members:
        cwe_counts.update(cve_to_cwes.get(cve, []))
    md = f"""# Typical Guideline Case: Attacker-Controlled JNDI Lookup Target

## Paper Use

This case is a compact example for explaining how GCA turns heterogeneous CVE records into a reusable audit guideline. The guideline is not a project signature: it describes a mechanism-level route from attacker-controlled lookup material into JNDI/LDAP/RMI naming APIs without same-path constraints on scheme, authority, object factory, object type, or destination.

## Example Case

| Field | Value |
| --- | --- |
| Identity | `{jndi['identity_key']}` |
| CVE | `{', '.join(jndi['cve_ids'])}` |
| Guideline ID | `{', '.join(jndi['guideline_ids'])}` |
| Mechanism ID | `{', '.join(jndi['mechanism_ids'])}` |
| Mechanism name | {', '.join(jndi['mechanism_names'])} |

## Released Retrieval Guideline

> {jndi['retrieval_guideline']}

## Why This Is A Good Paper Example

- The CWE labels around the same mechanism are heterogeneous: {', '.join(f'{k} ({v})' for k, v in cwe_counts.most_common()) or 'no joined CWE labels'}.
- The GCA mechanism appears across refined clusters {', '.join(str(x) for x in cluster_ids)}, showing that the reusable mechanism can be recovered even when the surrounding CVE/CWE space is noisy.
- The generated guideline names concrete audit handles: attacker-controlled names/URLs/configuration, JNDI/LDAP/RMI lookup sinks, scheme/destination/object-factory constraints, and same-path guard checking.
- This directly matches the paper narrative: GCA extracts a root-cause mechanism, online retrieval uses the mechanism text as the query, and the downstream auditor receives a focused investigation obligation.

## Mechanism Evidence Summary

| Item | Value |
| --- | --- |
| Active candidate groups | {len(jndi_candidates)} |
| Distinct historical CVEs in candidate groups | {len(all_members)} |
| Matched mechanism terms | {', '.join(matched_terms[:18])} |

## Suggested Figure Caption

GCA converts coarse and inconsistent CVE/CWE labels into mechanism-level audit guidelines. In this example, several historical vulnerabilities with different surrounding labels map to a single actionable mechanism: attacker-controlled JNDI lookup target. The resulting guideline supplies a reusable source-sink-guard obligation for repository-level retrieval and audit.
"""
    write(OUT_DIR / "typical_guideline_case.md", md)
    return {
        "identity": jndi["identity_key"],
        "guideline_ids": jndi["guideline_ids"],
        "mechanism_ids": jndi["mechanism_ids"],
        "candidate_groups": len(jndi_candidates),
        "historical_cves": len(all_members),
        "cwe_counts": dict(cwe_counts),
    }


def generate_gca_visuals() -> dict:
    summary = read_json(COVERAGE_SUMMARY)
    _, mechanism_to_cwes, cwe_to_mechanisms = build_mechanism_cwe_stats()
    coverage = summary["coverage_category_counts"]
    total = summary["identity_count"]
    funnel_rows = [
        ("Primary released sidecar", summary["coverage_upper_bounds"]["current_primary_sidecar"], "28 / 143"),
        (
            "Release current review queue",
            summary["coverage_upper_bounds"]["if_review_queue_released_for_current_candidates"],
            "53 / 143",
        ),
        (
            "Release noise/singleton candidates",
            summary["coverage_upper_bounds"]["if_noise_singletons_released_from_current_raw_structured"],
            "73 / 143",
        ),
        ("All CVE IDs ingested", summary["coverage_upper_bounds"]["if_all_cve_ids_ingested"], "136 / 143"),
        ("CVE + GHSA supported", summary["coverage_upper_bounds"]["if_cve_and_ghsa_supported"], "143 / 143"),
    ]
    bar_svg(
        "GCA coverage funnel on the 143-case paper set",
        "The primary release covers 28 cases; most remaining headroom is CVE/GHSA ingestion and release gating, not model scoring.",
        funnel_rows,
        OUT_DIR / "gca_coverage_funnel.svg",
    )

    cwe_rows = []
    for cwe, mechanisms in cwe_to_mechanisms.items():
        cwe_rows.append((cwe, len(mechanisms), mechanisms))
    cwe_rows = sorted(cwe_rows, key=lambda x: (x[1], sum(x[2].values())), reverse=True)[:10]
    bar_svg(
        "One CWE label maps to many GCA mechanisms",
        "Mechanism diversity under a CWE label exposes why CWE-only grouping is too coarse for retrieval queries.",
        [(cwe, n, f"{n} mechanisms") for cwe, n, _ in cwe_rows],
        OUT_DIR / "gca_cwe_to_mechanisms.svg",
    )

    mechanism_rows = []
    for mech, cwes in mechanism_to_cwes.items():
        mechanism_rows.append((mech, len(cwes), cwes))
    mechanism_rows = sorted(mechanism_rows, key=lambda x: (x[1], sum(x[2].values())), reverse=True)[:10]
    bar_svg(
        "One GCA mechanism can cross many CWE labels",
        "Mechanism-level grouping recovers shared audit obligations split across heterogeneous CVE/CWE annotations.",
        [(mech, n, f"{n} CWE labels") for mech, n, _ in mechanism_rows],
        OUT_DIR / "gca_mechanism_to_cwes.svg",
    )
    gca_space_contrast_svg(summary, cwe_rows, mechanism_rows, OUT_DIR / "gca_space_contrast.svg")

    md = ["# GCA vs CVE/CWE Visualization Notes", ""]
    md.append("## Coverage Funnel")
    md.append("")
    md.append("| Stage | Cases | Rate |")
    md.append("| --- | ---: | ---: |")
    for label, value, _ in funnel_rows:
        md.append(f"| {label} | {int(value)} / {total} | {pct(value, total)} |")
    md.append("")
    md.append("## Current Coverage Categories")
    md.append("")
    md.append("| Category | Count | Rate |")
    md.append("| --- | ---: | ---: |")
    for key, value in sorted(coverage.items(), key=lambda kv: kv[1], reverse=True):
        md.append(f"| `{key}` | {value} | {pct(value, total)} |")
    md.append("")
    md.append("## CWE Labels With Many GCA Mechanisms")
    md.append("")
    md.append("| CWE | Distinct mechanisms | Top mechanisms |")
    md.append("| --- | ---: | --- |")
    for cwe, n, mechanisms in cwe_rows[:8]:
        top = ", ".join(f"`{m}` ({c})" for m, c in mechanisms.most_common(4))
        md.append(f"| {cwe} | {n} | {top} |")
    md.append("")
    md.append("## GCA Mechanisms Spanning Many CWE Labels")
    md.append("")
    md.append("| Mechanism | Distinct CWE labels | Top CWE labels |")
    md.append("| --- | ---: | --- |")
    for mech, n, cwes in mechanism_rows[:8]:
        top = ", ".join(f"{cwe} ({count})" for cwe, count in cwes.most_common(5))
        md.append(f"| `{mech}` | {n} | {top} |")
    md.append("")
    md.append("## Paper Claim Boundary")
    md.append("")
    md.append(
        "These figures support a data-quality and query-construction claim: CWE/CVE metadata is too coarse or incomplete for direct retrieval queries, while GCA mechanism grouping creates more actionable audit obligations. They do not by themselves prove final vulnerability detection recall."
    )
    write(OUT_DIR / "gca_vs_cwe_notes.md", "\n".join(md) + "\n")
    return {
        "coverage_category_counts": coverage,
        "coverage_upper_bounds": summary["coverage_upper_bounds"],
        "top_cwe_mechanism_diversity": [
            {"cwe": cwe, "mechanism_count": n, "top_mechanisms": mechanisms.most_common(5)}
            for cwe, n, mechanisms in cwe_rows
        ],
        "top_mechanism_cwe_diversity": [
            {"mechanism": mech, "cwe_count": n, "top_cwes": cwes.most_common(5)}
            for mech, n, cwes in mechanism_rows
        ],
    }


def generate_p3c64_visuals() -> dict:
    p3_summary = read_json(P3C64_SUMMARY)["metrics"]
    comparison = read_json(QWEN4B_COMPARISON)
    qwen_metrics = read_json(QWEN4B_METRICS)
    p3_rows = {row["identity_key"]: row for row in read_jsonl(P3C64_RANKS)}
    qwen_rows = {row["identity_key"]: row for row in read_jsonl(QWEN4B_RANKS)}
    common = sorted(set(p3_rows) & set(qwen_rows))

    def saved_rank(row: dict) -> int:
        # A null rank means no known anchor was present in the saved rank range.
        # Place it just after the candidate list for ordering and visualization.
        rank = row.get("best_known_anchor_rank")
        if rank is None:
            return int(row.get("candidate_count") or 50000) + 1
        return int(rank)

    joined = []
    for ident in common:
        p3 = p3_rows[ident]
        q4 = qwen_rows[ident]
        joined.append(
            {
                "identity_key": ident,
                "hcvr_type": p3.get("hcvr_type"),
                "p3_rank": saved_rank(p3),
                "qwen_rank": saved_rank(q4),
                "p3_candidate_count": int(p3["candidate_count"]),
                "qwen_candidate_count": int(q4["candidate_count"]),
            }
        )
    grouped_hit_svg(comparison, OUT_DIR / "p3c64_hit_at_k.svg")
    rank_shift_svg(joined, OUT_DIR / "p3c64_rank_shift_examples.svg")
    p3c64_by_type_svg(joined, OUT_DIR / "p3c64_by_type_hit100.svg")

    improved = [d for d in joined if d["p3_rank"] < d["qwen_rank"]]
    worsened = [d for d in joined if d["p3_rank"] > d["qwen_rank"]]
    same = [d for d in joined if d["p3_rank"] == d["qwen_rank"]]
    left_only_200 = [d for d in joined if d["p3_rank"] <= 200 < d["qwen_rank"]]
    right_only_200 = [d for d in joined if d["qwen_rank"] <= 200 < d["p3_rank"]]
    illustrative = sorted(left_only_200, key=lambda d: (d["p3_rank"], -d["qwen_rank"]))[:12]
    by_type: dict[str, list[dict]] = defaultdict(list)
    for row in joined:
        by_type[row.get("hcvr_type") or "unknown"].append(row)
    type_rows = []
    for typ, items in by_type.items():
        if len(items) < 3:
            continue
        p3_100 = sum(1 for d in items if d["p3_rank"] <= 100)
        q4_100 = sum(1 for d in items if d["qwen_rank"] <= 100)
        p3_200 = sum(1 for d in items if d["p3_rank"] <= 200)
        q4_200 = sum(1 for d in items if d["qwen_rank"] <= 200)
        type_rows.append((typ, len(items), p3_100, q4_100, p3_200, q4_200))
    type_rows.sort(key=lambda r: ((r[2] - r[3]) + (r[4] - r[5]), r[1]), reverse=True)

    md = ["# P3C64 Same-Identity Retrieval Visualization Notes", ""]
    md.append("## Same-Identity Hit@K")
    md.append("")
    md.append("| Budget | P3C64 hits | Qwen3-Embedding-4B hits | Delta |")
    md.append("| ---: | ---: | ---: | ---: |")
    for k in [30, 50, 100, 200, 300, 500]:
        m = comparison["metrics_on_common_identities"][f"hit_at_{k}"]
        md.append(f"| {k} | {m['left_count']} | {m['right_count']} | +{m['delta_count']} |")
    md.append("")
    md.append("## Aggregate Rank Movement")
    md.append("")
    md.append("| Statistic | Value |")
    md.append("| --- | ---: |")
    md.append(f"| Common identities | {len(joined)} |")
    md.append(f"| Improved rank with P3C64 | {len(improved)} |")
    md.append(f"| Worsened rank with P3C64 | {len(worsened)} |")
    md.append(f"| Unchanged rank | {len(same)} |")
    md.append(f"| P3C64-only Top-200 cases | {len(left_only_200)} |")
    md.append(f"| Qwen4B-only Top-200 cases | {len(right_only_200)} |")
    md.append(f"| Median P3C64 rank | {median(d['p3_rank'] for d in joined):.0f} |")
    md.append(f"| Median Qwen4B rank | {median(d['qwen_rank'] for d in joined):.0f} |")
    md.append(f"| P3C64 MRR | {p3_summary['mrr']:.4f} |")
    md.append(f"| Qwen4B MRR | {qwen_metrics['mrr_all_cases']:.4f} |")
    md.append("")
    md.append("## Illustrative Cases Entering Top-200 With P3C64")
    md.append("")
    md.append("| Identity | Type | Qwen4B rank | P3C64 rank |")
    md.append("| --- | --- | ---: | ---: |")
    for d in illustrative:
        md.append(f"| `{d['identity_key']}` | `{d['hcvr_type']}` | {d['qwen_rank']} | {d['p3_rank']} |")
    md.append("")
    md.append("## By-Type Movement")
    md.append("")
    md.append("| HCVR type | Cases | P3C64 Top100 | Qwen4B Top100 | P3C64 Top200 | Qwen4B Top200 |")
    md.append("| --- | ---: | ---: | ---: | ---: | ---: |")
    for typ, n, p3_100, q4_100, p3_200, q4_200 in type_rows:
        md.append(f"| `{typ}` | {n} | {p3_100} | {q4_100} | {p3_200} | {q4_200} |")
    md.append("")
    md.append("## Paper Claim Boundary")
    md.append("")
    md.append(
        "This material supports the claim that P3C64 improves mechanism-conditioned known-anchor ranking on the same 143 identities. It is a retrieval-quality visualization. A stronger embedding-geometry claim should be backed by nearest-neighbor or projection plots from saved embedding vectors."
    )
    md.append("")
    md.append(
        "Null saved ranks are interpreted as one position after the candidate list because the known anchor was not present in the saved rank range."
    )
    write(OUT_DIR / "p3c64_visualization_notes.md", "\n".join(md) + "\n")
    return {
        "same_identity_count": len(joined),
        "improved_rank_count": len(improved),
        "worsened_rank_count": len(worsened),
        "same_rank_count": len(same),
        "p3c64_only_top200_count": len(left_only_200),
        "qwen4b_only_top200_count": len(right_only_200),
        "median_p3c64_rank": median(d["p3_rank"] for d in joined),
        "median_qwen4b_rank": median(d["qwen_rank"] for d in joined),
        "by_type_rows": [
            {
                "hcvr_type": typ,
                "case_count": n,
                "p3c64_top100": p3_100,
                "qwen4b_top100": q4_100,
                "p3c64_top200": p3_200,
                "qwen4b_top200": q4_200,
            }
            for typ, n, p3_100, q4_100, p3_200, q4_200 in type_rows
        ],
    }


def generate_paper_snippets(summaries: dict) -> None:
    g = summaries["guideline_case"]
    upper = summaries["gca"]["coverage_upper_bounds"]
    p = summaries["p3c64"]
    md = f"""# Paper Snippets

## Guideline Case Paragraph

GCA produces mechanism-level guidelines that are more actionable than a raw CVE or CWE label. A representative example is `{g['mechanism_ids'][0]}`, the attacker-controlled JNDI lookup target guideline. The released guideline asks the auditor to trace attacker-controlled names, URLs, headers, configuration values, or lookup keys into JNDI, LDAP, RMI, naming-context, or remote lookup APIs, and to verify same-path constraints on scheme, authority, object factory, object type, and network destination. The example case `{g['identity']}` is attached to guideline `{g['guideline_ids'][0]}`. Across the candidate groups behind this mechanism, {g['historical_cves']} historical CVEs map through heterogeneous CWE labels, including {', '.join(f'{k} ({v})' for k, v in sorted(g['cwe_counts'].items(), key=lambda kv: kv[1], reverse=True)[:5])}. This illustrates the paper's central use case: the online system receives a reusable security obligation rather than a project-specific signature.

## GCA Figure Caption

GCA separates vulnerability mechanism space from noisy CVE/CWE annotation space. On the 143-case paper set, the released primary sidecar covers {upper['current_primary_sidecar']} cases, while the audited headroom reaches {upper['if_review_queue_released_for_current_candidates']} cases after current review-queue release, {upper['if_noise_singletons_released_from_current_raw_structured']} cases after raw/noise candidate release, and {upper['if_all_cve_ids_ingested']} cases when all CVE IDs are ingested. The paired fan-out views show that one CWE can decompose into many mechanisms and one reusable mechanism can cross several CWE labels.

## P3C64 Figure Caption

P3C64 improves mechanism-conditioned known-anchor retrieval under the same 143 evaluation identities. Compared with Qwen3-Embedding-4B, P3C64 raises Hit@30 from 30 to 45, Hit@50 from 37 to 56, Hit@100 from 55 to 73, and Hit@200 from 74 to 84. The rank-shift view highlights cases that enter the Top-200 only after P3C64 adaptation, including TOCTOU, authorization, state-precondition, file-permission, and IRIS-style cases. The evidence supports improved mechanism-conditioned ranking; saved embedding vectors are needed for a direct embedding-geometry visualization.
"""
    write(OUT_DIR / "paper_snippets.md", md)


def generate_readme(summaries: dict) -> None:
    md = f"""# Paper Material Pack: GCA Case Study and P3C64 Retrieval Figures

Generated on 2026-08-25 from existing `new-impl/new-guideline/results` artifacts.

## Contents

| File | Purpose |
| --- | --- |
| `typical_guideline_case.md` | Paper-ready JNDI guideline case study. |
| `gca_coverage_funnel.svg` | Coverage/headroom visualization for the 143-case paper set. |
| `gca_space_contrast.svg` | One-slide CVE/CWE annotation space vs GCA mechanism space contrast. |
| `gca_cwe_to_mechanisms.svg` | Shows coarse CWE labels splitting into multiple GCA mechanisms. |
| `gca_mechanism_to_cwes.svg` | Shows reusable GCA mechanisms crossing multiple CWE labels. |
| `gca_vs_cwe_notes.md` | Tables and claim boundaries for the GCA figures. |
| `p3c64_hit_at_k.svg` | Same-identity Hit@K comparison between P3C64 and Qwen3-Embedding-4B. |
| `p3c64_rank_shift_examples.svg` | Representative rank shifts where P3C64 brings cases into Top-200. |
| `p3c64_by_type_hit100.svg` | Per-HCVR-type Top-100 comparison for semantic-family discussion. |
| `p3c64_visualization_notes.md` | Tables and claim boundaries for P3C64 figures. |
| `paper_snippets.md` | Short paper-ready paragraphs and captions. |
| `material_summary.json` | Machine-readable summary of the generated material. |
| `generate_materials.py` | Reproducible generator using only Python standard library. |

## Key Numbers

- GCA primary released sidecar coverage: {summaries['gca']['coverage_upper_bounds']['current_primary_sidecar']} / 143.
- GCA coverage upper bound if all CVE IDs are ingested: {summaries['gca']['coverage_upper_bounds']['if_all_cve_ids_ingested']} / 143.
- P3C64 Hit@100: 73 / 143; Qwen3-Embedding-4B Hit@100: 55 / 143; delta: +18 cases.
- P3C64 Hit@200: 84 / 143; Qwen3-Embedding-4B Hit@200: 74 / 143; delta: +10 cases.
- P3C64-only Top-200 cases: {summaries['p3c64']['p3c64_only_top200_count']}; Qwen4B-only Top-200 cases: {summaries['p3c64']['qwen4b_only_top200_count']}.

## Provenance

- Coverage audit: `{COVERAGE_SUMMARY.relative_to(REPO_ROOT)}` and `{CASE_COVERAGE.relative_to(REPO_ROOT)}`.
- Guideline sidecar: `{GUIDELINE_OVERRIDES.relative_to(REPO_ROOT)}`.
- Mechanism candidates: `{MECHANISM_CANDIDATES.relative_to(REPO_ROOT)}`.
- Structured CVE join: `{STRUCTURED_CVES}`.
- P3C64 evaluation: `{P3C64_SUMMARY.relative_to(REPO_ROOT)}` and `{P3C64_RANKS.relative_to(REPO_ROOT)}`.
- Qwen4B comparison: `{QWEN4B_METRICS.relative_to(REPO_ROOT)}` and `{QWEN4B_RANKS.relative_to(REPO_ROOT)}`.

## Claim Boundaries

- Use the GCA figures for metadata quality, cluster/mechanism construction, and guideline release coverage. Use separate audit receipts for final audit precision or confirmed vulnerability recall.
- Use the P3C64 figures for same-identity known-anchor retrieval. They support a mechanism-conditioned ranking improvement claim; a direct geometric semantics claim should use saved embedding-vector projections or nearest-neighbor evidence.
- Use the JNDI case study as a guideline example derived from the release-ready sidecar. Pair it with source-level evidence when presenting a full end-to-end case study.
"""
    write(OUT_DIR / "README.md", md)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    summaries = {
        "guideline_case": generate_guideline_case(),
        "gca": generate_gca_visuals(),
        "p3c64": generate_p3c64_visuals(),
    }
    write(OUT_DIR / "material_summary.json", json.dumps(summaries, indent=2, ensure_ascii=False) + "\n")
    generate_paper_snippets(summaries)
    generate_readme(summaries)
    print(f"Wrote paper material pack to {OUT_DIR}")


if __name__ == "__main__":
    main()
