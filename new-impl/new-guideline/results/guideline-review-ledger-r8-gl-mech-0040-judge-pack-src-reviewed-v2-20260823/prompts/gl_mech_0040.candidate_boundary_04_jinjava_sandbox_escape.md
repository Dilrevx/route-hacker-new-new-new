# Guideline Semantic Judge Rubric

You are judging a reusable security-audit guideline group.

Evaluate whether the guideline accurately describes a coherent vulnerability
mechanism shared by the listed cases.

Do not evaluate embedding recall, rank, or whether known anchors were hit.
Do not require all cases to share the same CWE or dataset label; those labels
are only weak context.

Prefer mechanism-level judgments:

- source shape
- sink shape
- missing guard
- exploit precondition
- safe fix

Return JSON only with this schema:

```json
{
  "decision": "accept|revise|split|merge|needs_evidence",
  "coherence_score": 0.0,
  "coverage_score": 0.0,
  "actionability_score": 0.0,
  "retrieval_query_quality": 0.0,
  "main_issue": "short explanation",
  "suggested_guideline": "rewrite if decision is revise or split",
  "split_suggestions": ["submechanism A", "submechanism B"],
  "evidence_notes": ["case-level evidence or missing evidence"]
}
```

Ledger-specific instructions:
{
  "decision_values": [
    "accept",
    "revise",
    "split",
    "merge",
    "needs_evidence"
  ],
  "expected_json": {
    "actionability_score": 0.0,
    "coherence_score": 0.0,
    "coverage_score": 0.0,
    "decision": "accept|revise|split|merge|needs_evidence",
    "evidence_notes": [
      "case-level evidence or missing evidence"
    ],
    "main_issue": "short explanation",
    "retrieval_query_quality": 0.0,
    "split_suggestions": [
      "submechanism A",
      "submechanism B"
    ],
    "suggested_guideline": "rewrite if decision is revise or split"
  },
  "review_scope": [
    "Judge semantic boundary quality only.",
    "Check whether source shape, sink/effect, missing guard, exploit precondition, and safe fix are coherent.",
    "Check whether representative cases support the boundary decision.",
    "Do not judge embedding recall, known-anchor rank, Top-K metrics, or model performance.",
    "Do not invent new source evidence. If evidence is insufficient, return needs_evidence.",
    "Do not call tools, do not run shell commands, and do not try to write files; return the JSON object as the final answer only."
  ],
  "task": "Review one source-reviewed guideline boundary ledger row."
}

Ledger boundary payload:
{
  "judge_mode": "source_reviewed_boundary_advisory",
  "ledger_row": {
    "boundary_decision": "promote_boundary",
    "boundary_label": "candidate_boundary_04_jinjava_sandbox_escape",
    "boundary_text": "Jinjava sandbox bypass through incomplete property or method restrictions: attacker-controlled template expressions reach Jinjava EL/property/method resolution and can access interpreter internals, restricted classes, reflection packages, Jackson databind objects, or direct JavaBean read methods because the resolver does not consistently apply sandbox restrictions to the base object, method name, package, or property access path. Report flows where property or method resolution bypasses the interpreter's restricted-class and restricted-method checks.",
    "evidence_refs": [
      {
        "identity_key": "hubspot__jinjava::CVE-2020-12668",
        "source_evidence": "Fix commit 1b9aaa4b... adds JinjavaInterpreter to restricted classes in isRestrictedClass, confirming that interpreter object access from templates was not fully blocked."
      },
      {
        "identity_key": "hubspot__jinjava::CVE-2025-59340",
        "source_evidence": "Fix commit 66df351e... adds if (isRestrictedClass(base)) return null; in getValue and tests the payload {{ ____int3rpr3t3r____.config }}, confirming the missing guard on restricted base objects during property resolution."
      },
      {
        "identity_key": "hubspot__jinjava::CVE-2026-25526",
        "source_evidence": "Fix commit 3d02e504... adds restricted method readValueAs, restricts java.lang.reflect and com.fasterxml.jackson.databind packages, and changes ForTag property extraction from direct valProp.getReadMethod().invoke(val) to interpreter.resolveProperty(val, valProp.getName())."
      }
    ],
    "exploit_precondition": "An attacker can submit or influence a Jinjava template expression that is evaluated by the server in a context where sandbox restrictions are expected to prevent access to interpreter internals, restricted classes, reflection packages, or dangerous methods.",
    "guideline_id": "gl_mech_0040",
    "mechanism_id": "mech_jinjava_sandbox_property_method_escape",
    "mechanism_name": "Jinjava sandbox bypass through incomplete property or method restrictions",
    "missing_guard": "The vulnerable paths lack consistent restricted-class, restricted-base-object, restricted-package, restricted-method, and sandbox-aware property resolution checks at the resolver and tag property access points. Direct JavaBean read-method invocation bypasses the interpreter's normal sandbox-aware resolution path.",
    "rationale": "The source/fix evidence consistently points to incomplete Jinjava sandbox restrictions at property and method resolution boundaries. The three cases share a concrete source, sink, missing guard, and fix family.",
    "recall_follow_up": "After a sidecar change, rerun same-identity recall on the three hubspot__jinjava cases. If misses persist, check whether source slicing captures JinjavaBeanELResolver, ForTag, restricted method lists, package restrictions, and interpreter.resolveProperty changes.",
    "representative_cases": [
      "hubspot__jinjava::CVE-2020-12668",
      "hubspot__jinjava::CVE-2025-59340",
      "hubspot__jinjava::CVE-2026-25526"
    ],
    "reviewer_notes": "This is a Jinjava-specific sandbox-bypass mechanism. It can remain within the broad template-expression family for taxonomy, but should be a separate recall/audit guideline because its useful query terms are Jinjava, EL resolver, restricted class, restricted method, package restriction, interpreter internals, and sandbox-aware property resolution.",
    "safe_fix_semantics": "Extend the restricted class/package/method set, reject restricted base objects in getValue, and route property reads through interpreter.resolveProperty or an equivalent sandbox-aware resolver so the same restrictions apply across direct property access, method invocation, package access, and tag iteration paths.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "Jinjava EL property/method resolution can disclose or invoke dangerous interpreter internals, reflection capabilities, Jackson databind methods, or object properties that should be inaccessible from sandboxed templates.",
    "source_shape": "The reviewed cases all involve attacker-controlled Jinjava template expressions evaluated through JinjavaBeanELResolver or related tag/property resolution code. The vulnerable resolver exposes interpreter objects, restricted base objects, restricted methods, packages, or direct bean read methods to template expressions."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.