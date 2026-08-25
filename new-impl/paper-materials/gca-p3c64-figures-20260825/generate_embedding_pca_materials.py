#!/usr/bin/env python3
"""Generate embedding PCA figures for CWE/GCA and P3C64 query geometry.

This script is designed to run on bobo5090 where numpy, sklearn, torch, and the
embedding model are available. It can also run elsewhere if the same
dependencies and embedding endpoint/model paths are present.
"""

from __future__ import annotations

import argparse
import html
import json
import math
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score


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
]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def l2_normalize(vectors: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return vectors / norms


def openai_embed(texts: list[str], *, base_url: str, model: str, batch_size: int) -> np.ndarray:
    vectors: list[list[float]] = []
    for start in range(0, len(texts), batch_size):
        batch = texts[start : start + batch_size]
        payload = json.dumps({"model": model, "input": batch}).encode("utf-8")
        request = urllib.request.Request(
            base_url.rstrip("/") + "/embeddings",
            data=payload,
            headers={"Content-Type": "application/json", "Connection": "close"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=600) as response:
            data = json.loads(response.read().decode("utf-8"))
        items = sorted(data.get("data") or [], key=lambda item: int(item.get("index", 0)))
        if len(items) != len(batch):
            raise RuntimeError(f"embedding endpoint returned {len(items)} vectors for {len(batch)} texts")
        vectors.extend(item["embedding"] for item in items)
    return l2_normalize(np.asarray(vectors, dtype=np.float32))


def p3c64_embed_queries(
    texts: list[str],
    *,
    model_path: str,
    state_path: Path,
    device: str,
    batch_size: int,
    hidden_dimension: int,
    residual_scale: float,
) -> tuple[np.ndarray, np.ndarray]:
    import torch
    import torch.nn.functional as F
    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer(model_path, device=device)
    base = model.encode(
        texts,
        batch_size=batch_size,
        normalize_embeddings=True,
        show_progress_bar=False,
        convert_to_numpy=True,
    ).astype(np.float32)
    try:
        state = torch.load(state_path, map_location="cpu", weights_only=True)
    except TypeError:
        state = torch.load(state_path, map_location="cpu")
    required = {
        "query_projection.first.weight",
        "query_projection.first.bias",
        "query_projection.output.weight",
        "query_projection.output.bias",
    }
    if set(state) != required:
        raise ValueError(f"unexpected P3C64 state keys: {sorted(state)}")
    if base.shape[1] != 1024:
        raise ValueError(f"P3C64 state expects 1024-dimensional base embeddings, got {base.shape}")
    first_weight = state["query_projection.first.weight"].float()
    first_bias = state["query_projection.first.bias"].float()
    output_weight = state["query_projection.output.weight"].float()
    output_bias = state["query_projection.output.bias"].float()
    if tuple(first_weight.shape) != (hidden_dimension, 1024):
        raise ValueError(f"unexpected first weight shape: {tuple(first_weight.shape)}")
    with torch.inference_mode():
        x = torch.as_tensor(base, dtype=torch.float32)
        hidden = F.gelu(F.linear(x, first_weight, first_bias))
        delta = F.linear(hidden, output_weight, output_bias)
        adapted = F.normalize(x + float(residual_scale) * delta, p=2, dim=-1).cpu().numpy()
    return l2_normalize(base), l2_normalize(adapted.astype(np.float32))


def apply_p3c64_residual(
    base_vectors: np.ndarray,
    *,
    state_path: Path,
    hidden_dimension: int,
    residual_scale: float,
) -> np.ndarray:
    """Apply the P3C64 query residual on precomputed base embeddings using CPU."""
    import torch
    import torch.nn.functional as F

    try:
        state = torch.load(state_path, map_location="cpu", weights_only=True)
    except TypeError:
        state = torch.load(state_path, map_location="cpu")
    required = {
        "query_projection.first.weight",
        "query_projection.first.bias",
        "query_projection.output.weight",
        "query_projection.output.bias",
    }
    if set(state) != required:
        raise ValueError(f"unexpected P3C64 state keys: {sorted(state)}")
    if base_vectors.shape[1] != 1024:
        raise ValueError(f"P3C64 state expects 1024-dimensional base embeddings, got {base_vectors.shape}")
    first_weight = state["query_projection.first.weight"].float()
    first_bias = state["query_projection.first.bias"].float()
    output_weight = state["query_projection.output.weight"].float()
    output_bias = state["query_projection.output.bias"].float()
    if tuple(first_weight.shape) != (hidden_dimension, 1024):
        raise ValueError(f"unexpected first weight shape: {tuple(first_weight.shape)}")
    with torch.inference_mode():
        x = torch.as_tensor(base_vectors, dtype=torch.float32, device="cpu")
        hidden = F.gelu(F.linear(x, first_weight, first_bias))
        delta = F.linear(hidden, output_weight, output_bias)
        adapted = F.normalize(x + float(residual_scale) * delta, p=2, dim=-1).cpu().numpy()
    return l2_normalize(adapted.astype(np.float32))


def cve_text(row: dict[str, Any]) -> str:
    fields = [
        row.get("vuln_type") or "",
        row.get("root_cause") or "",
        row.get("abstract_pattern") or "",
        row.get("data_flow") or "",
        row.get("trigger_condition") or "",
        row.get("fix_strategy") or "",
    ]
    return "\n".join(part for part in fields if part).strip()


def short_mechanism(mech: str) -> str:
    value = mech.removeprefix("mech_")
    replacements = {
        "ssrf_webhook_url_fetch": "SSRF webhook fetch",
        "path_traversal_missing_canonical_prefix": "path canonical guard",
        "jndi_untrusted_lookup_target": "JNDI lookup target",
        "template_expression_untrusted_eval": "template eval",
        "xml_external_entity_resolution": "XXE resolution",
        "open_redirect_unsafe_uri_scheme": "open redirect URI",
        "object_owner_scope_missing_authz": "owner-scope authz",
        "sql_dynamic_query_untrusted_fragment": "dynamic SQL fragment",
        "deserialization_untrusted_type_graph": "deserialization type graph",
    }
    if value in replacements:
        return replacements[value]
    return value.replace("_", " ")[:28]


def build_cve_points(
    *,
    structured_cves: Path,
    mechanism_candidates: Path,
    top_mechanisms: int,
    top_cwes: int,
    max_points: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    cve_rows = {row["cve_id"]: row for row in read_jsonl(structured_cves) if cve_text(row)}
    best_by_cve: dict[str, dict[str, Any]] = {}
    mechanism_counts: Counter[str] = Counter()
    for candidate in read_jsonl(mechanism_candidates):
        mech = candidate.get("mechanism_id") or ""
        if not mech or mech.startswith("pending_") or candidate.get("status") != "active":
            continue
        for cve in candidate.get("members") or []:
            if cve not in cve_rows:
                continue
            mechanism_counts[mech] += 1
            score = (
                float(candidate.get("alignment_score") or 0.0),
                int(candidate.get("evidence_role_count") or 0),
                int(candidate.get("member_count") or 0),
            )
            existing = best_by_cve.get(cve)
            if existing is None or score > existing["score"]:
                best_by_cve[cve] = {
                    "score": score,
                    "mechanism_id": mech,
                    "mechanism_name": candidate.get("mechanism_name") or short_mechanism(mech),
                    "mechanism_family": candidate.get("mechanism_family") or "unknown",
                    "cluster_id": candidate.get("cluster_id"),
                    "cluster_name": candidate.get("cluster_name") or "",
                }
    selected_mechanisms = {mech for mech, _ in mechanism_counts.most_common(top_mechanisms)}
    cwe_counts: Counter[str] = Counter()
    for cve, link in best_by_cve.items():
        if link["mechanism_id"] not in selected_mechanisms:
            continue
        cwe_counts.update(cve_rows[cve].get("cwe_chain") or [])
    selected_cwes = {cwe for cwe, _ in cwe_counts.most_common(top_cwes)}
    points: list[dict[str, Any]] = []
    for cve, link in best_by_cve.items():
        if link["mechanism_id"] not in selected_mechanisms:
            continue
        row = cve_rows[cve]
        cwes = row.get("cwe_chain") or []
        primary_cwe = cwes[0] if cwes else "CWE-unknown"
        points.append(
            {
                "id": cve,
                "text": cve_text(row),
                "primary_cwe": primary_cwe if primary_cwe in selected_cwes else "Other CWE",
                "raw_primary_cwe": primary_cwe,
                "cwe_chain": cwes,
                "mechanism_id": link["mechanism_id"],
                "mechanism_label": short_mechanism(link["mechanism_id"]),
                "mechanism_family": link["mechanism_family"],
                "cluster_id": link["cluster_id"],
                "cluster_name": link["cluster_name"],
                "vuln_type": row.get("vuln_type") or "",
            }
        )
    points.sort(key=lambda row: (row["mechanism_id"], row["id"]))
    if max_points > 0:
        points = points[:max_points]
    metadata = {
        "selected_mechanisms": mechanism_counts.most_common(top_mechanisms),
        "selected_cwes": cwe_counts.most_common(top_cwes),
        "candidate_cve_count": len(best_by_cve),
        "point_count": len(points),
    }
    return points, metadata


def build_guideline_points(
    *,
    guideline_overrides: Path,
    mechanism_candidates: Path,
    top_mechanisms: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    mech_family: dict[str, str] = {}
    mech_count: Counter[str] = Counter()
    for candidate in read_jsonl(mechanism_candidates):
        mech = candidate.get("mechanism_id") or ""
        if not mech or mech.startswith("pending_"):
            continue
        mech_family.setdefault(mech, candidate.get("mechanism_family") or "unknown")
    overrides = read_jsonl(guideline_overrides)
    for row in overrides:
        for mech in row.get("mechanism_ids") or []:
            mech_count[mech] += 1
    selected = {mech for mech, _ in mech_count.most_common(top_mechanisms)}
    seen_texts: set[tuple[str, str]] = set()
    points: list[dict[str, Any]] = []
    for row in overrides:
        mechanisms = [m for m in row.get("mechanism_ids") or [] if m in selected]
        if not mechanisms:
            continue
        mech = mechanisms[0]
        text = row.get("retrieval_guideline") or ""
        key = (mech, text)
        if key in seen_texts:
            continue
        seen_texts.add(key)
        points.append(
            {
                "id": row.get("guideline_ids", [""])[0] or row.get("case_id") or "",
                "identity_key": row.get("identity_key") or "",
                "text": text,
                "mechanism_id": mech,
                "mechanism_label": short_mechanism(mech),
                "mechanism_family": mech_family.get(mech, "unknown"),
            }
        )
    points.sort(key=lambda row: (row["mechanism_id"], row["id"]))
    return points, {"selected_mechanisms": mech_count.most_common(top_mechanisms), "point_count": len(points)}


def pca_project(vectors: np.ndarray) -> tuple[np.ndarray, dict[str, float]]:
    pca = PCA(n_components=2, random_state=0)
    xy = pca.fit_transform(vectors)
    # Stabilize orientation for deterministic SVGs.
    if np.corrcoef(xy[:, 0], np.arange(len(xy)))[0, 1] < 0:
        xy[:, 0] *= -1
    if np.corrcoef(xy[:, 1], np.arange(len(xy)))[0, 1] < 0:
        xy[:, 1] *= -1
    return xy, {
        "pc1_explained_variance": float(pca.explained_variance_ratio_[0]),
        "pc2_explained_variance": float(pca.explained_variance_ratio_[1]),
    }


def scaled(points: np.ndarray, x: float, y: float, w: float, h: float) -> np.ndarray:
    mins = points.min(axis=0)
    maxs = points.max(axis=0)
    spans = np.maximum(maxs - mins, 1e-8)
    norm = (points - mins) / spans
    return np.column_stack([x + norm[:, 0] * w, y + (1.0 - norm[:, 1]) * h])


def label_colors(labels: list[str]) -> dict[str, str]:
    counts = Counter(labels)
    ordered = [label for label, _ in counts.most_common()]
    return {label: PALETTE[index % len(PALETTE)] for index, label in enumerate(ordered)}


def knn_agreement(vectors: np.ndarray, labels: list[str], k: int = 10) -> float:
    if len(vectors) <= k:
        return 0.0
    sims = vectors @ vectors.T
    agreements = []
    for i, label in enumerate(labels):
        order = np.argsort(-sims[i])
        neighbors = [j for j in order if j != i][:k]
        agreements.append(sum(1 for j in neighbors if labels[j] == label) / k)
    return float(np.mean(agreements))


def fmt_metric(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.2f}"


def safe_silhouette(vectors: np.ndarray, labels: list[str]) -> float | None:
    counts = Counter(labels)
    usable = [label for label, count in counts.items() if count >= 2]
    if len(usable) < 2:
        return None
    indices = [i for i, label in enumerate(labels) if label in usable]
    if len(indices) <= len(usable):
        return None
    try:
        return float(silhouette_score(vectors[indices], [labels[i] for i in indices], metric="cosine"))
    except Exception:
        return None


def scatter_panel(
    parts: list[str],
    *,
    title: str,
    subtitle: str,
    xy: np.ndarray,
    labels: list[str],
    colors: dict[str, str],
    x: int,
    y: int,
    w: int,
    h: int,
) -> None:
    pts = scaled(xy, x, y, w, h)
    parts.append(f'<text class="panel-title" x="{x}" y="{y - 38}">{esc(title)}</text>')
    parts.append(f'<text class="small" x="{x}" y="{y - 18}">{esc(subtitle)}</text>')
    parts.append(f'<rect class="panel" x="{x}" y="{y}" width="{w}" height="{h}" rx="4"/>')
    parts.append(f'<line class="axis" x1="{x + w/2:.1f}" y1="{y}" x2="{x + w/2:.1f}" y2="{y + h}"/>')
    parts.append(f'<line class="axis" x1="{x}" y1="{y + h/2:.1f}" x2="{x + w}" y2="{y + h/2:.1f}"/>')
    for (px, py), label in zip(pts, labels):
        color = colors.get(label, "#b0bec5")
        opacity = "0.35" if label.startswith("Other") else "0.82"
        radius = "3.0" if label.startswith("Other") else "4.2"
        parts.append(f'<circle cx="{px:.1f}" cy="{py:.1f}" r="{radius}" fill="{color}" opacity="{opacity}"/>')


def legend(parts: list[str], *, colors: dict[str, str], x: int, y: int, title: str, max_items: int = 10) -> None:
    parts.append(f'<text class="legend-title" x="{x}" y="{y}">{esc(title)}</text>')
    yy = y + 22
    for index, (label, color) in enumerate(colors.items()):
        if index >= max_items:
            break
        shown = label if len(label) <= 28 else label[:25] + "..."
        parts.append(f'<rect x="{x}" y="{yy - 12}" width="12" height="12" rx="2" fill="{color}"/>')
        parts.append(f'<text class="legend" x="{x + 18}" y="{yy - 2}">{esc(shown)}</text>')
        yy += 19


def write_cve_gca_svg(
    path: Path,
    *,
    xy: np.ndarray,
    points: list[dict[str, Any]],
    pca_stats: dict[str, float],
    cwe_knn: float,
    mechanism_knn: float,
    cwe_silhouette: float | None,
    mechanism_silhouette: float | None,
) -> None:
    cwe_labels = [p["primary_cwe"] for p in points]
    mechanism_labels = [p["mechanism_label"] for p in points]
    cwe_colors = label_colors(cwe_labels)
    mechanism_colors = label_colors(mechanism_labels)
    width, height = 1180, 720
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<style><![CDATA[",
        "text{font-family:Arial,Helvetica,sans-serif;fill:#17202a}.title{font-size:24px;font-weight:700}",
        ".subtitle{font-size:13px;fill:#5d6d7e}.panel-title{font-size:17px;font-weight:700}.small{font-size:12px;fill:#5d6d7e}",
        ".panel{fill:#fbfcfd;stroke:#ccd6dd;stroke-width:1}.axis{stroke:#e5eaee;stroke-width:1}.legend-title{font-size:13px;font-weight:700}.legend{font-size:12px;fill:#34495e}",
        ".metric{font-size:13px;font-weight:700}.note{font-size:12px;fill:#5d6d7e}",
        "]]></style>",
        '<rect width="1180" height="720" fill="white"/>',
    ]
    panel_y, panel_w, panel_h = 116, 420, 420
    scatter_panel(
        parts,
        title="Colored by primary CWE",
        subtitle=f"10-NN same-label={cwe_knn:.2f}; silhouette={fmt_metric(cwe_silhouette)}",
        xy=xy,
        labels=cwe_labels,
        colors=cwe_colors,
        x=40,
        y=panel_y,
        w=panel_w,
        h=panel_h,
    )
    scatter_panel(
        parts,
        title="Colored by GCA mechanism",
        subtitle=f"10-NN same-label={mechanism_knn:.2f}; silhouette={fmt_metric(mechanism_silhouette)}",
        xy=xy,
        labels=mechanism_labels,
        colors=mechanism_colors,
        x=520,
        y=panel_y,
        w=panel_w,
        h=panel_h,
    )
    legend(parts, colors=cwe_colors, x=40, y=586, title="CWE legend", max_items=7)
    legend(parts, colors=mechanism_colors, x=520, y=586, title="GCA mechanism legend", max_items=7)
    parts.append(
        f'<text class="note" x="960" y="130">PC1 {pca_stats["pc1_explained_variance"]:.1%}</text>'
    )
    parts.append(
        f'<text class="note" x="960" y="150">PC2 {pca_stats["pc2_explained_variance"]:.1%}</text>'
    )
    parts.append('<text class="note" x="960" y="190">Use: motivation figure</text>')
    parts.append('<text class="note" x="960" y="210">Same dots, two labels.</text>')
    parts.append('<text class="note" x="960" y="230">CWE mixes mechanisms;</text>')
    parts.append('<text class="note" x="960" y="250">GCA gives audit intent.</text>')
    parts.append("</svg>")
    path.write_text("\n".join(parts), encoding="utf-8")


def write_p3c64_svg(
    path: Path,
    *,
    base_xy: np.ndarray,
    adapted_xy: np.ndarray,
    points: list[dict[str, Any]],
    base_stats: dict[str, float],
    adapted_stats: dict[str, float],
    base_knn: float,
    adapted_knn: float,
    base_silhouette: float | None,
    adapted_silhouette: float | None,
) -> None:
    labels = [p["mechanism_label"] for p in points]
    colors = label_colors(labels)
    width, height = 1180, 720
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<style><![CDATA[",
        "text{font-family:Arial,Helvetica,sans-serif;fill:#17202a}.title{font-size:24px;font-weight:700}",
        ".subtitle{font-size:13px;fill:#5d6d7e}.panel-title{font-size:17px;font-weight:700}.small{font-size:12px;fill:#5d6d7e}",
        ".panel{fill:#fbfcfd;stroke:#ccd6dd;stroke-width:1}.axis{stroke:#e5eaee;stroke-width:1}.legend-title{font-size:13px;font-weight:700}.legend{font-size:12px;fill:#34495e}.note{font-size:12px;fill:#5d6d7e}",
        "]]></style>",
        '<rect width="1180" height="720" fill="white"/>',
    ]
    panel_y, panel_w, panel_h = 116, 420, 420
    scatter_panel(
        parts,
        title="Base Qwen query embedding",
        subtitle=f"10-NN same-mechanism={base_knn:.2f}; silhouette={fmt_metric(base_silhouette)}",
        xy=base_xy,
        labels=labels,
        colors=colors,
        x=40,
        y=panel_y,
        w=panel_w,
        h=panel_h,
    )
    scatter_panel(
        parts,
        title="P3C64 adapted query embedding",
        subtitle=f"10-NN same-mechanism={adapted_knn:.2f}; silhouette={fmt_metric(adapted_silhouette)}",
        xy=adapted_xy,
        labels=labels,
        colors=colors,
        x=520,
        y=panel_y,
        w=panel_w,
        h=panel_h,
    )
    legend(parts, colors=colors, x=40, y=586, title="Mechanism legend", max_items=9)
    parts.append(f'<text class="note" x="960" y="130">Base PC1 {base_stats["pc1_explained_variance"]:.1%}</text>')
    parts.append(f'<text class="note" x="960" y="150">Base PC2 {base_stats["pc2_explained_variance"]:.1%}</text>')
    parts.append(f'<text class="note" x="960" y="184">P3C64 PC1 {adapted_stats["pc1_explained_variance"]:.1%}</text>')
    parts.append(f'<text class="note" x="960" y="204">P3C64 PC2 {adapted_stats["pc2_explained_variance"]:.1%}</text>')
    parts.append('<text class="note" x="960" y="244">Use: adapter diagnostic.</text>')
    parts.append('<text class="note" x="960" y="264">Pair with Hit@K table.</text>')
    parts.append("</svg>")
    path.write_text("\n".join(parts), encoding="utf-8")


def write_p3c64_cve_shift_svg(
    path: Path,
    *,
    base_xy: np.ndarray,
    adapted_xy: np.ndarray,
    points: list[dict[str, Any]],
    base_stats: dict[str, float],
    adapted_stats: dict[str, float],
    base_knn: float,
    adapted_knn: float,
    base_silhouette: float | None,
    adapted_silhouette: float | None,
) -> None:
    labels = [p["mechanism_label"] for p in points]
    colors = label_colors(labels)
    width, height = 1180, 720
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<style><![CDATA[",
        "text{font-family:Arial,Helvetica,sans-serif;fill:#17202a}.title{font-size:24px;font-weight:700}",
        ".subtitle{font-size:13px;fill:#5d6d7e}.panel-title{font-size:17px;font-weight:700}.small{font-size:12px;fill:#5d6d7e}",
        ".panel{fill:#fbfcfd;stroke:#ccd6dd;stroke-width:1}.axis{stroke:#e5eaee;stroke-width:1}.legend-title{font-size:13px;font-weight:700}.legend{font-size:12px;fill:#34495e}.note{font-size:12px;fill:#5d6d7e}",
        "]]></style>",
        '<rect width="1180" height="720" fill="white"/>',
    ]
    panel_y, panel_w, panel_h = 116, 420, 420
    scatter_panel(
        parts,
        title="Base query embedding",
        subtitle=f"10-NN same-mechanism={base_knn:.2f}; silhouette={fmt_metric(base_silhouette)}",
        xy=base_xy,
        labels=labels,
        colors=colors,
        x=40,
        y=panel_y,
        w=panel_w,
        h=panel_h,
    )
    scatter_panel(
        parts,
        title="P3C64 adapted query embedding",
        subtitle=f"10-NN same-mechanism={adapted_knn:.2f}; silhouette={fmt_metric(adapted_silhouette)}",
        xy=adapted_xy,
        labels=labels,
        colors=colors,
        x=520,
        y=panel_y,
        w=panel_w,
        h=panel_h,
    )
    legend(parts, colors=colors, x=40, y=586, title="Mechanism legend", max_items=9)
    parts.append(f'<text class="note" x="960" y="130">Base PC1 {base_stats["pc1_explained_variance"]:.1%}</text>')
    parts.append(f'<text class="note" x="960" y="150">Base PC2 {base_stats["pc2_explained_variance"]:.1%}</text>')
    parts.append(f'<text class="note" x="960" y="184">P3C64 PC1 {adapted_stats["pc1_explained_variance"]:.1%}</text>')
    parts.append(f'<text class="note" x="960" y="204">P3C64 PC2 {adapted_stats["pc2_explained_variance"]:.1%}</text>')
    parts.append('<text class="note" x="960" y="244">Use: semantic diagnostic.</text>')
    parts.append('<text class="note" x="960" y="264">Primary evidence is Hit@K.</text>')
    parts.append("</svg>")
    path.write_text("\n".join(parts), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--structured-cves", type=Path, required=True)
    parser.add_argument("--mechanism-candidates", type=Path, required=True)
    parser.add_argument("--guideline-overrides", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--embedding-base-url", default="http://127.0.0.1:8001/v1")
    parser.add_argument("--embedding-model", default="Qwen/Qwen3-Embedding-0.6B")
    parser.add_argument("--p3c64-base-model", default="/data/lhq/workspace/hcvr-embedding-service/models/Qwen3-Embedding-0.6B")
    parser.add_argument("--p3c64-state", type=Path, default=Path("/data/lhq/workspace/p3-hard-competition-query-adapter-v1/selection_run_v1/p3c64_state.pt"))
    parser.add_argument("--device", default="cuda:0")
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--top-mechanisms", type=int, default=9)
    parser.add_argument("--top-cwes", type=int, default=9)
    parser.add_argument("--max-cve-points", type=int, default=260)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    cve_points, cve_meta = build_cve_points(
        structured_cves=args.structured_cves,
        mechanism_candidates=args.mechanism_candidates,
        top_mechanisms=args.top_mechanisms,
        top_cwes=args.top_cwes,
        max_points=args.max_cve_points,
    )
    if len(cve_points) < 10:
        raise RuntimeError(f"too few CVE points for PCA: {len(cve_points)}")
    cve_vectors = openai_embed(
        [p["text"] for p in cve_points],
        base_url=args.embedding_base_url,
        model=args.embedding_model,
        batch_size=args.batch_size,
    )
    cve_xy, cve_pca_stats = pca_project(cve_vectors)
    cwe_labels = [p["primary_cwe"] for p in cve_points]
    mechanism_labels = [p["mechanism_label"] for p in cve_points]
    cwe_knn = knn_agreement(cve_vectors, cwe_labels)
    mechanism_knn = knn_agreement(cve_vectors, mechanism_labels)
    cwe_sil = safe_silhouette(cve_vectors, cwe_labels)
    mech_sil = safe_silhouette(cve_vectors, mechanism_labels)
    write_cve_gca_svg(
        args.output_dir / "embedding_pca_cwe_vs_gca.svg",
        xy=cve_xy,
        points=cve_points,
        pca_stats=cve_pca_stats,
        cwe_knn=cwe_knn,
        mechanism_knn=mechanism_knn,
        cwe_silhouette=cwe_sil,
        mechanism_silhouette=mech_sil,
    )

    guideline_points, guideline_meta = build_guideline_points(
        guideline_overrides=args.guideline_overrides,
        mechanism_candidates=args.mechanism_candidates,
        top_mechanisms=args.top_mechanisms,
    )
    if len(guideline_points) < 10:
        raise RuntimeError(f"too few guideline points for PCA: {len(guideline_points)}")
    base_vectors = openai_embed(
        [p["text"] for p in guideline_points],
        base_url=args.embedding_base_url,
        model=args.embedding_model,
        batch_size=args.batch_size,
    )
    adapted_vectors = apply_p3c64_residual(
        base_vectors,
        state_path=args.p3c64_state,
        hidden_dimension=128,
        residual_scale=0.1,
    )
    base_xy, base_pca_stats = pca_project(base_vectors)
    adapted_xy, adapted_pca_stats = pca_project(adapted_vectors)
    guideline_labels = [p["mechanism_label"] for p in guideline_points]
    base_knn = knn_agreement(base_vectors, guideline_labels)
    adapted_knn = knn_agreement(adapted_vectors, guideline_labels)
    base_sil = safe_silhouette(base_vectors, guideline_labels)
    adapted_sil = safe_silhouette(adapted_vectors, guideline_labels)
    write_p3c64_svg(
        args.output_dir / "embedding_pca_p3c64_query_shift.svg",
        base_xy=base_xy,
        adapted_xy=adapted_xy,
        points=guideline_points,
        base_stats=base_pca_stats,
        adapted_stats=adapted_pca_stats,
        base_knn=base_knn,
        adapted_knn=adapted_knn,
        base_silhouette=base_sil,
        adapted_silhouette=adapted_sil,
    )

    cve_base_vectors = cve_vectors
    cve_adapted_vectors = apply_p3c64_residual(
        cve_base_vectors,
        state_path=args.p3c64_state,
        hidden_dimension=128,
        residual_scale=0.1,
    )
    cve_base_xy, cve_base_pca_stats = pca_project(cve_base_vectors)
    cve_adapted_xy, cve_adapted_pca_stats = pca_project(cve_adapted_vectors)
    cve_mechanism_labels = [p["mechanism_label"] for p in cve_points]
    cve_base_knn = knn_agreement(cve_base_vectors, cve_mechanism_labels)
    cve_adapted_knn = knn_agreement(cve_adapted_vectors, cve_mechanism_labels)
    cve_base_sil = safe_silhouette(cve_base_vectors, cve_mechanism_labels)
    cve_adapted_sil = safe_silhouette(cve_adapted_vectors, cve_mechanism_labels)
    write_p3c64_cve_shift_svg(
        args.output_dir / "embedding_pca_p3c64_cve_hypothesis_shift.svg",
        base_xy=cve_base_xy,
        adapted_xy=cve_adapted_xy,
        points=cve_points,
        base_stats=cve_base_pca_stats,
        adapted_stats=cve_adapted_pca_stats,
        base_knn=cve_base_knn,
        adapted_knn=cve_adapted_knn,
        base_silhouette=cve_base_sil,
        adapted_silhouette=cve_adapted_sil,
    )

    rows = []
    for point, xy in zip(cve_points, cve_xy.tolist()):
        row = dict(point)
        row.pop("text", None)
        row["pca_x"] = xy[0]
        row["pca_y"] = xy[1]
        rows.append(row)
    with (args.output_dir / "embedding_pca_cve_points.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    guideline_rows = []
    for point, base_xy_row, adapted_xy_row in zip(guideline_points, base_xy.tolist(), adapted_xy.tolist()):
        row = dict(point)
        row.pop("text", None)
        row["base_pca_x"] = base_xy_row[0]
        row["base_pca_y"] = base_xy_row[1]
        row["p3c64_pca_x"] = adapted_xy_row[0]
        row["p3c64_pca_y"] = adapted_xy_row[1]
        guideline_rows.append(row)
    with (args.output_dir / "embedding_pca_guideline_points.jsonl").open("w", encoding="utf-8") as handle:
        for row in guideline_rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    summary = {
        "schema_version": "paper_embedding_pca.v1",
        "embedding_model": args.embedding_model,
        "embedding_base_url": args.embedding_base_url,
        "p3c64_base_model": args.p3c64_base_model,
        "p3c64_state": str(args.p3c64_state),
        "cve_points": cve_meta,
        "guideline_points": guideline_meta,
        "cve_pca": cve_pca_stats,
        "cwe_knn_same_label_at_10": cwe_knn,
        "gca_mechanism_knn_same_label_at_10": mechanism_knn,
        "cwe_silhouette_cosine": cwe_sil,
        "gca_mechanism_silhouette_cosine": mech_sil,
        "base_guideline_pca": base_pca_stats,
        "p3c64_guideline_pca": adapted_pca_stats,
        "base_guideline_knn_same_mechanism_at_10": base_knn,
        "p3c64_guideline_knn_same_mechanism_at_10": adapted_knn,
        "base_guideline_silhouette_cosine": base_sil,
        "p3c64_guideline_silhouette_cosine": adapted_sil,
        "base_cve_hypothesis_pca": cve_base_pca_stats,
        "p3c64_cve_hypothesis_pca": cve_adapted_pca_stats,
        "base_cve_hypothesis_knn_same_mechanism_at_10": cve_base_knn,
        "p3c64_cve_hypothesis_knn_same_mechanism_at_10": cve_adapted_knn,
        "base_cve_hypothesis_silhouette_cosine": cve_base_sil,
        "p3c64_cve_hypothesis_silhouette_cosine": cve_adapted_sil,
    }
    write_json(args.output_dir / "embedding_pca_summary.json", summary)
    notes = [
        "# Embedding PCA Notes",
        "",
        "## Figures",
        "",
        "- `embedding_pca_cwe_vs_gca.svg`: same CVE root-cause embedding coordinates, colored once by primary CWE and once by GCA mechanism.",
        "- `embedding_pca_p3c64_query_shift.svg`: released guideline texts before and after the P3C64 query residual adapter.",
        "- `embedding_pca_p3c64_cve_hypothesis_shift.svg`: CVE root-cause hypothesis texts before and after the P3C64 query residual adapter.",
        "",
        "## Quantitative Diagnostics",
        "",
        f"- CVE points: {len(cve_points)}.",
        f"- CWE 10-NN same-label agreement: {cwe_knn:.3f}.",
        f"- GCA mechanism 10-NN same-label agreement: {mechanism_knn:.3f}.",
        f"- Base guideline 10-NN same-mechanism agreement: {base_knn:.3f}.",
        f"- P3C64 guideline 10-NN same-mechanism agreement: {adapted_knn:.3f}.",
        f"- Base CVE-hypothesis 10-NN same-mechanism agreement: {cve_base_knn:.3f}.",
        f"- P3C64 CVE-hypothesis 10-NN same-mechanism agreement: {cve_adapted_knn:.3f}.",
        "",
        "## Claim Boundary",
        "",
        "Use the first figure as the visual motivation for replacing direct CWE-space grouping with mechanism-level GCA grouping.",
        "Use the second figure as an adapter diagnostic and pair it with the Hit@K table; the retrieval metrics remain the primary P3C64 evidence.",
    ]
    (args.output_dir / "embedding_pca_notes.md").write_text("\n".join(notes) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
