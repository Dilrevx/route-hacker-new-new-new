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
| `coder__coder::CVE-2026-55435` | Top160 hit, rank 15 | TP=0, FP=4, FN=1 | a low-line AI-bridge anchor was dismissed without following the same-file delegated API-key authorization path | [case.md](coder__coder__CVE-2026-55435/case.md) |
| `dspace__dspace::CVE-2025-53621` | Top160 hit, ranks 131 and 137 | TP=0, FP=7, FN=1 | two truth-overlapping import/XML-service anchors were dismissed before minimal downstream sink review | [case.md](dspace__dspace__CVE-2025-53621/case.md) |
| `earendil-works__pi::CVE-2026-54327` | Top160 hit, rank 6 | TP=0, FP=6, FN=1 | truth-overlapping auth-storage implementation window was inaccurately dismissed as imports/type definitions | [case.md](earendil-works__pi__CVE-2026-54327/case.md) |
| `erudika__para::CVE-2025-48955` | Top160 hit, rank 32 | TP=0, FP=7, FN=1 | recalled source-localized root-credential logging/configuration window was dismissed as outside a request-driven untrusted-data path | [case.md](erudika__para__CVE-2025-48955/case.md) |
| `ethyca__fides::CVE-2026-42303` | Top160 hits, ranks 111 and 127 | TP=0, FP=6, FN=1 | duplicate-request approval windows were dismissed/risk-tagged without a truth-localizing finding for the identity-verification precondition | [case.md](ethyca__fides__CVE-2026-42303/case.md) |
| `filamentphp__filament::CVE-2026-48505` | Top160 hits, ranks 10 and 29 | TP=0, FP=6, FN=1 | a recovered-code validation window was risk-tagged but not converted into a truth-localizing finding | [case.md](filamentphp__filament__CVE-2026-48505/case.md) |
| `hal__console::CVE-2025-2901` | Top160 hits, ranks 18 and 152 | TP=0, FP=4, FN=1 | two source-localized URL/storage anchors were dismissed without a truth-localizing finding | [case.md](hal__console__CVE-2025-2901/case.md) |
| `jandedobbeleer__oh-my-posh::GHSA-6XJ8-QV9J-XCJQ` | Top160 hits, ranks 35, 57, 69, and 132 | TP=0, FP=4, FN=1 | four source-overlapping runtime windows were dismissed and alarms shifted to non-truth locations | [case.md](jandedobbeleer__oh-my-posh__GHSA-6XJ8-QV9J-XCJQ/case.md) |
| `jenkinsci__oic-auth-plugin::CVE-2025-24399` | Top160 hits, ranks 15, 20, 37, 44, and 48 | TP=0, FP=3, FN=1 | recalled OIDC login and Jenkins identity-resolution windows were dismissed in favor of non-truth alarms | [case.md](jenkinsci__oic-auth-plugin__CVE-2025-24399/case.md) |
| `mezz__justenoughitems::CVE-2024-41565` | Top160 hit, rank 128 | TP=0, FP=5, FN=1 | truth-overlapping transfer precondition window was risk-tagged, but the emitted packet-path alarm did not localize either frozen truth span | [case.md](mezz__justenoughitems__CVE-2024-41565/case.md) |
| `nyariv__sandboxjs::CVE-2026-32723` | Top160 hits, ranks 45, 68, 73, 89, and 149 | TP=0, FP=3, FN=1 | shared tick-budget windows were dismissed while the audit emitted non-truth mutable-method-call alarms | [case.md](nyariv__sandboxjs__CVE-2026-32723/case.md) |
