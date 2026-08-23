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
| `apache__iotdb::CVE-2025-26864` | Top160 hit, rank 4 | TP=0, FP=8, FN=1 | truth hunk vs. emitted vulnerable-method span; audit reached `validateToken` but scorer accepts only lines 151-153 / 165 | [case.md](apache__iotdb__CVE-2025-26864/case.md) |
| `apache__sling-org-apache-sling-xss::CVE-2016-5394` | Top160 hit, rank 9 | TP=0, FP=7, FN=1 | interface-caller-implementation JavaScript-encoding chain was retrieved but displaced by unrelated XSS/XML alarms | [case.md](apache__sling-org-apache-sling-xss__CVE-2016-5394/case.md) |
| `arcadedata__arcadedb::CVE-2026-44221` | Top160 hit, rank 12 | TP=0, FP=11, FN=1 | recalled API-token authentication / synthetic-principal flow was explicitly dismissed as root-gated administration | [case.md](arcadedata__arcadedb__CVE-2026-44221/case.md) |
