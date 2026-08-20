# Bad-case Handoff: Stage-2 Grouped Audit and Guideline Quality

## Purpose

This handoff records a concrete failure mode discovered while preparing the
Unified V2 30-case Qwen3-Embedding-4B feasibility audit. It separates the
stage-2 execution repair from the remaining guideline-quality work, so that
guideline refinement can proceed without changing candidate grouping, scoring,
or the audit harness contract.

## Current 143-Case Retrieval Evidence

The current fixed-identity 143-case P3C64 result and bad-case analysis are
stored in:

```text
results/p3c64-fixed143-paper-eval-20260820/
```

Use this directory, rather than the older `--selection all --limit 143`
artifact, for paper-facing comparison against Qwen3-Embedding-4B.

| Budget | Qwen3-Embedding-4B | P3C64 query-residual | Delta |
| --- | ---: | ---: | ---: |
| Top-100 | 55/143 = 0.3846 | 73/143 = 0.5105 | +18 cases / +12.6 pp |
| Top-150 | 65/143 = 0.4545 | 83/143 = 0.5804 | +18 cases / +12.6 pp |
| Top-200 | 74/143 = 0.5175 | 84/143 = 0.5874 | +10 cases / +7.0 pp |

The Top-100 miss set has 70 cases. Eleven of them have the first known anchor
ranked 101-200, which is the most realistic next recovery target. The largest
Top-100 miss bucket is `iris` with 20 cases, matching the guideline-quality
failure mode below.

## Execution repair now on this branch

The stage-2 harness consumes the selected Top-K anchors as independent,
directory-local groups of ten anchors. For Top-K=200, all 200 candidates are
covered by twenty groups. A group has a separate prompt, raw event log, final
JSON report, and timeout. The case-level receipt aggregates all group findings
without discarding multiple findings.

The grouping is deterministic: the lowest-rank unassigned anchor begins a
group, and the nearest remaining anchors in the repository directory tree fill
that group; retrieval rank resolves ties. Grouping changes execution locality
only. Every selected anchor remains present exactly once.

Each audit worker receives exactly ten candidates and is instructed to:

1. Apply the supplied guideline as the sole vulnerability family.
2. Quickly dismiss candidates that cannot plausibly implement that family.
3. Perform read-only exploration only over the smallest local caller/callee,
   guard, data-flow, state-transition, and sensitive-effect path needed to
   resolve plausible candidates.
4. Return a disposition for every candidate and emit a finding only for a
   concrete, localized in-scope risk.

This replaces the prior single Top-200 open-ended agent session, which kept
exploring repository-wide and repeatedly timed out without returning JSON.

## Observed bad guideline

The first real recall case used HCVR type `m9_wave4` and the following prompt:

```text
Audit whether the anchor participates in a guideline-derived semantic security
pattern where attacker-influenced input, resource identity, or execution
context reaches a sensitive effect without the required validation,
authorization, isolation, or state precondition.
```

This is too broad to be a useful audit obligation. It simultaneously admits
input validation, authorization, isolation, and state-precondition failures,
so an auditor can reasonably inspect unrelated security directions. The grouped
execution protocol prevents unbounded exploration, but it cannot make this
prompt a narrow vulnerability-type instruction.

## Desired guideline contract

A released guideline must define one small semantic vulnerability family and
state the required relation between its relevant entities. For example, a
guideline for incorrect SQL pattern matching should direct the audit toward
pattern construction and matching semantics; it should not authorize a generic
SQL-injection search. Likewise, a resource-scoped authorization guideline
should name the principal, requested child resource, authoritative parent or
tenant scope, and the missing ownership/binding check.

Guidelines used in normal stage-2 prompts must not contain a CVE ID, original
case description, vulnerable method name, patch, advisory text, historical PoC,
or evaluation-trace location. Those data remain outside the audit prompt.

## Acceptance checklist for guideline optimization

- The text names one narrow vulnerability family rather than a disjunction of
  generic security properties.
- It identifies the expected input/resource/state entities and the required
  relation or invariant among them.
- It states the relevant sensitive effect and the missing or incorrect
  condition to check.
- It tells the auditor what nearby but out-of-family vulnerability classes to
  ignore when that distinction is necessary.
- It is reusable across a family of repositories and versions; it does not
  encode case-specific ground truth.
- Its provenance is recorded and it is frozen/hashed before use in a reported
  evaluation.

## Audit prompt contract after optimization

The stage-2 prompt remains type-conditioned and instructs the auditor to return
one disposition per candidate (`risk`, `dismissed`, or
`insufficient_evidence`) plus zero or more localized findings. Optimizing the
guideline should therefore only replace the `Audit obligation` text; it should
not change Top-K, 10-anchor grouping, runner/model, candidate list, timeout,
or TP/FP/FN scorer when comparing results.

## Relevant implementation

- `scripts/run_hcvr_ablation_a.py`: deterministic directory-local grouping,
  one audit session per group, all group logs, and aggregation.
- `tests/test_hcvr_ablation_a.py`: verifies Top-K coverage exactly once,
  directory-local grouping, bounded group prompt behavior, multi-finding
  preservation, and case-level scoring.
- `/Users/bytedance/tmp/hcvr-ablation-a-30-v2allow-20260818T164555/grouped10_prompt_preview_agentfront_group001.txt`:
  local, non-versioned real prompt preview generated from the first 30-case
  recall row.
