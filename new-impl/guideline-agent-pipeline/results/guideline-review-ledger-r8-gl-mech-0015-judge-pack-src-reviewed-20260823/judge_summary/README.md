# Guideline LLM Judge Summary

This report summarizes TraeX/LLM-as-judge outputs for guideline group quality.
It is separate from embedding recall and should be used as advisory semantic evidence for guideline iteration, not as a hard scoring target.
Low scores and non-accept decisions identify groups worth reading; they should not be converted into keyword rules or hidden routing logic.

## Summary

- Judge inputs: 1
- Parsed outputs: 1
- Missing outputs: 0
- Invalid outputs: 0
- Accepted groups: 1
- Needs revision/split/merge/evidence: 0
- Low-score groups: 1 at threshold 0.6
- Decision counts: {'accept': 1}
- Average scores: {'coherence_score': 0.9, 'coverage_score': 0.3, 'actionability_score': 0.7, 'retrieval_query_quality': 0.8}

## Highest Priority Rows

- `gl_mech_0015` `mech_predictable_archive_member_temp_path_check_write_race`: decision=accept, min_score=0.3, issue=The mechanism is semantically coherent across all five dimensions (source shape, sink, missing guard, exploit precondition, safe fix), and the single representative case (psf__requests::CVE-2026-25645) cleanly supports the boundary. The reviewer notes already acknowledge this is a narrow single-case mechanism; the boundary does not overclaim scope. The tempfile.mkstemp fix is well-defined and the exploit precondition is concrete.
