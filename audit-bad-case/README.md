# Audit Bad Cases

This directory records **audit-stage** failures from the fixed P3C64 Unified V2
Backend-B protocol. A case is added only after its finalized score receipt shows
that Top-K recall reached a truth-overlapping anchor but the bounded audit emitted
no truth-localizing finding. These records are diagnostic evidence, not changes to
the frozen evaluation input, scorer, prompt, recall result, or paper metrics.

Each case directory contains the fixed identity/revision, recall placement, audit
group evidence, source-localized truth evidence, final score, and a proposed
follow-up that must be evaluated in a separate experiment.

| Case | Recall status | Final audit status | Failure class | Record |
| --- | --- | --- | --- | --- |
| `apache__activemq::CVE-2020-11998` | Top160 hit, rank 109 | TP=0, FP=6, FN=1 | truth-adjacent window; audit did not inspect preceding vulnerable method | [case.md](apache__activemq__CVE-2020-11998/case.md) |
