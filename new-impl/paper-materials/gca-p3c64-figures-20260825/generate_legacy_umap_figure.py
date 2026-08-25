#!/usr/bin/env python3
"""Render the legacy CVE-clustering UMAP coordinates as a paper figure.

The source coordinates are produced by the historical
`scripts/compute_cluster_coords.py` pipeline in route-hacker. This renderer
does not recompute embeddings or UMAP; it only turns the saved coordinates into
an SVG with the same point positions colored two ways.
"""

from __future__ import annotations

import html
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
INPUT = ROOT / "legacy_umap_coords_2d.json"
OUTPUT = ROOT / "legacy_umap_cwe_vs_guideline.svg"
SUMMARY = ROOT / "legacy_umap_summary.json"

PALETTE = [
    "#2878b5",
    "#d1495b",
    "#1f8f72",
    "#e58f65",
    "#7e57c2",
    "#455a64",
    "#f2b134",
    "#00a6a6",
    "#9c6644",
    "#5c6bc0",
    "#8d6e63",
    "#c2185b",
]


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def short_cluster(value: str) -> str:
    lower = value.lower()
    rules = [
        ("path canonicalization", "Path containment"),
        ("authentication and authorization", "AuthN/AuthZ guard"),
        ("cross-site scripting", "XSS rendering"),
        ("deserialization", "Deserialization filter"),
        ("xml parser", "XXE parser config"),
        ("structured string", "Structured injection"),
        ("host validation", "SSRF host validation"),
        ("dynamic sql", "Dynamic SQL"),
        ("unsafe path construction", "Unsafe path construction"),
        ("template", "Template evaluation"),
        ("command", "Command execution"),
        ("redirect", "Redirect validation"),
        ("race", "Race condition"),
    ]
    for needle, label in rules:
        if needle in lower:
            return label
    words = value.replace("-", " ").replace("_", " ").split()
    return " ".join(words[:3]) if words else "Noise"


def top_label(raw: str, selected: set[str], other: str) -> str:
    value = raw or other
    return value if value in selected else other


def label_colors(labels: list[str]) -> dict[str, str]:
    ordered = [label for label, _ in Counter(labels).most_common()]
    return {label: PALETTE[i % len(PALETTE)] for i, label in enumerate(ordered)}


def scaled_point(point: dict[str, Any], x: int, y: int, w: int, h: int) -> tuple[float, float]:
    px = x + float(point["x"]) * w
    py = y + (1.0 - float(point["y"])) * h
    return px, py


def knn_same_label(points: list[dict[str, Any]], label_key: str, k: int = 10) -> float:
    total = 0
    same = 0
    coords = [(float(p["x"]), float(p["y"])) for p in points]
    labels = [str(p.get(label_key) or "") for p in points]
    for i, (x, y) in enumerate(coords):
        distances: list[tuple[float, int]] = []
        for j, (xx, yy) in enumerate(coords):
            if i == j:
                continue
            distances.append(((x - xx) * (x - xx) + (y - yy) * (y - yy), j))
        for _, j in sorted(distances)[:k]:
            total += 1
            if labels[i] == labels[j]:
                same += 1
    return same / total if total else 0.0


def draw_panel(
    parts: list[str],
    *,
    points: list[dict[str, Any]],
    label_key: str,
    colors: dict[str, str],
    x: int,
    y: int,
    w: int,
    h: int,
    label: str,
    metric: str,
) -> None:
    parts.append(f'<text class="panel-label" x="{x}" y="{y - 16}">{esc(label)}</text>')
    parts.append(f'<text class="metric" x="{x + w - 190}" y="{y - 16}">{esc(metric)}</text>')
    parts.append(f'<rect class="panel" x="{x}" y="{y}" width="{w}" height="{h}" rx="4"/>')
    parts.append(f'<line class="axis" x1="{x + w / 2:.1f}" y1="{y}" x2="{x + w / 2:.1f}" y2="{y + h}"/>')
    parts.append(f'<line class="axis" x1="{x}" y1="{y + h / 2:.1f}" x2="{x + w}" y2="{y + h / 2:.1f}"/>')
    for point in points:
        value = str(point.get(label_key) or "")
        px, py = scaled_point(point, x, y, w, h)
        opacity = "0.28" if value.startswith("Other") or value == "Noise" else "0.78"
        radius = "2.3" if value.startswith("Other") or value == "Noise" else "3.2"
        parts.append(f'<circle cx="{px:.1f}" cy="{py:.1f}" r="{radius}" fill="{colors.get(value, "#b0bec5")}" opacity="{opacity}"/>')


def draw_legend(parts: list[str], *, labels: list[str], colors: dict[str, str], x: int, y: int) -> None:
    yy = y
    for label in labels:
        shown = label if len(label) <= 24 else label[:21] + "..."
        parts.append(f'<rect x="{x}" y="{yy - 10}" width="10" height="10" rx="2" fill="{colors[label]}"/>')
        parts.append(f'<text class="legend" x="{x + 16}" y="{yy - 1}">{esc(shown)}</text>')
        yy += 18


def main() -> None:
    rows = json.loads(INPUT.read_text(encoding="utf-8"))
    top_cwes = {label for label, _ in Counter((r.get("cwe_id") or "N/A") for r in rows).most_common(9)}
    top_clusters = {
        label
        for label, _ in Counter((r.get("cluster_name") or "Noise") for r in rows if int(r.get("cluster_id", -1)) >= 0).most_common(9)
    }

    points: list[dict[str, Any]] = []
    for row in rows:
        cwe_label = top_label(str(row.get("cwe_id") or "N/A"), top_cwes, "Other CWE")
        raw_cluster = str(row.get("cluster_name") or "Noise")
        cluster_label = "Noise" if raw_cluster == "Noise" else top_label(raw_cluster, top_clusters, "Other clusters")
        points.append(
            {
                "x": row["x"],
                "y": row["y"],
                "cwe_label": cwe_label,
                "cluster_label": short_cluster(cluster_label) if cluster_label not in {"Noise", "Other clusters"} else cluster_label,
                "raw_cluster": raw_cluster,
                "cve_id": row.get("cve_id"),
            }
        )

    cwe_labels = [str(p["cwe_label"]) for p in points]
    cluster_labels = [str(p["cluster_label"]) for p in points]
    cwe_colors = label_colors(cwe_labels)
    cluster_colors = label_colors(cluster_labels)
    cwe_knn = knn_same_label(points, "cwe_label")
    cluster_knn = knn_same_label(points, "cluster_label")

    width, height = 1160, 650
    left_x, right_x, panel_y, panel_w, panel_h = 36, 500, 58, 420, 420
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<style><![CDATA[",
        "text{font-family:Arial,Helvetica,sans-serif;fill:#17202a}",
        ".panel-label{font-size:16px;font-weight:700}.metric{font-size:12px;fill:#5d6d7e}",
        ".panel{fill:#fbfcfd;stroke:#ccd6dd;stroke-width:1}.axis{stroke:#e5eaee;stroke-width:1}",
        ".legend{font-size:11px;fill:#34495e}.small{font-size:11px;fill:#5d6d7e}",
        "]]></style>",
        f'<rect width="{width}" height="{height}" fill="white"/>',
    ]
    draw_panel(
        parts,
        points=points,
        label_key="cwe_label",
        colors=cwe_colors,
        x=left_x,
        y=panel_y,
        w=panel_w,
        h=panel_h,
        label="CWE labels",
        metric=f"10-NN same={cwe_knn:.2f}",
    )
    draw_panel(
        parts,
        points=points,
        label_key="cluster_label",
        colors=cluster_colors,
        x=right_x,
        y=panel_y,
        w=panel_w,
        h=panel_h,
        label="Guideline clusters",
        metric=f"10-NN same={cluster_knn:.2f}",
    )
    draw_legend(parts, labels=list(cwe_colors)[:10], colors=cwe_colors, x=36, y=516)
    draw_legend(parts, labels=list(cluster_colors)[:10], colors=cluster_colors, x=500, y=516)
    parts.append('<text class="small" x="938" y="86">Legacy UMAP</text>')
    parts.append(f'<text class="small" x="938" y="106">{len(points)} CVE points</text>')
    parts.append('<text class="small" x="938" y="126">Same coordinates</text>')
    parts.append('<text class="small" x="938" y="146">Different labels</text>')
    parts.append("</svg>")
    OUTPUT.write_text("\n".join(parts), encoding="utf-8")

    cluster_counts = Counter(cluster_labels)
    write = {
        "source_coords": str(INPUT),
        "source_remote": "/data/lhq/workspace/route-hacker/output/cve_clustering/v1/coords_2d.json",
        "points": len(points),
        "raw_cwe_count": len({r.get("cwe_id") or "N/A" for r in rows}),
        "raw_cluster_count": len({r.get("cluster_name") or "Noise" for r in rows}),
        "display_cwe_labels": list(cwe_colors),
        "display_cluster_labels": list(cluster_colors),
        "umap_2d_knn_same_cwe_label_at_10": cwe_knn,
        "umap_2d_knn_same_guideline_cluster_at_10": cluster_knn,
        "noise_points": cluster_counts.get("Noise", 0),
    }
    SUMMARY.write_text(json.dumps(write, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT}")
    print(f"wrote {SUMMARY}")


if __name__ == "__main__":
    main()
