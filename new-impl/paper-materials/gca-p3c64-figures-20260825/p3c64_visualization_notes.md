# P3C64 Same-Identity Retrieval Visualization Notes

## Same-Identity Hit@K

| Budget | P3C64 hits | Qwen3-Embedding-4B hits | Delta |
| ---: | ---: | ---: | ---: |
| 30 | 45 | 30 | +15 |
| 50 | 56 | 37 | +19 |
| 100 | 73 | 55 | +18 |
| 200 | 84 | 74 | +10 |
| 300 | 91 | 82 | +9 |
| 500 | 103 | 94 | +9 |

## Aggregate Rank Movement

| Statistic | Value |
| --- | ---: |
| Common identities | 143 |
| Improved rank with P3C64 | 95 |
| Worsened rank with P3C64 | 43 |
| Unchanged rank | 5 |
| P3C64-only Top-200 cases | 22 |
| Qwen4B-only Top-200 cases | 12 |
| Median P3C64 rank | 95 |
| Median Qwen4B rank | 166 |
| P3C64 MRR | 0.0885 |
| Qwen4B MRR | 0.0507 |

## Illustrative Cases Entering Top-200 With P3C64

| Identity | Type | Qwen4B rank | P3C64 rank |
| --- | --- | ---: | ---: |
| `envoyproxy__gateway::CVE-2026-53715` | `toctou_check_use_race` | 2647 | 2 |
| `jeecgboot__jeecgboot::CVE-2025-14909` | `authorization_bypass` | 1360 | 2 |
| `getkin__kin-openapi::GHSA-R277-6W6Q-XMQW` | `m9_wave4` | 554 | 3 |
| `cyberjunky__python-garminconnect::CVE-2026-54447` | `file_permission_temp_resource` | 347 | 3 |
| `earendil-works__pi::CVE-2026-54327` | `m9_expansion` | 2064 | 6 |
| `filamentphp__filament::CVE-2026-48505` | `business_state_precondition` | 2141 | 10 |
| `coder__coder::CVE-2026-55435` | `m9_expansion` | 5073 | 15 |
| `jandedobbeleer__oh-my-posh::GHSA-6XJ8-QV9J-XCJQ` | `m9_wave4` | 339 | 35 |
| `nesquena__hermes-webui::CVE-2026-6830` | `concurrent_object_lifecycle` | 203 | 43 |
| `cuba-platform__cuba::CVE-2025-32959` | `iris` | 745 | 52 |
| `apache__commons-fileupload::CVE-2025-48976` | `iris` | 310 | 64 |
| `graylog2__graylog2-server::CVE-2025-53106` | `authorization_bypass` | 226 | 72 |

## By-Type Movement

| HCVR type | Cases | P3C64 Top100 | Qwen4B Top100 | P3C64 Top200 | Qwen4B Top200 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `iris` | 47 | 27 | 20 | 31 | 28 |
| `m9_expansion` | 3 | 3 | 0 | 3 | 0 |
| `m9_wave4` | 6 | 3 | 1 | 3 | 1 |
| `business_state_precondition` | 14 | 5 | 4 | 8 | 6 |
| `ssrf` | 4 | 3 | 2 | 4 | 2 |
| `toctou_check_use_race` | 10 | 4 | 2 | 4 | 4 |
| `file_permission_temp_resource` | 9 | 5 | 4 | 5 | 4 |
| `authentication_session_token_validation` | 10 | 7 | 6 | 7 | 7 |
| `concurrent_object_lifecycle` | 12 | 6 | 6 | 7 | 7 |
| `m9_wave2` | 5 | 1 | 1 | 1 | 1 |
| `open_redirect` | 4 | 4 | 4 | 4 | 4 |
| `authorization_bypass` | 15 | 5 | 5 | 6 | 8 |

## Paper Claim Boundary

This material supports the claim that P3C64 improves mechanism-conditioned known-anchor ranking on the same 143 identities. It is a retrieval-quality visualization. A stronger embedding-geometry claim should be backed by nearest-neighbor or projection plots from saved embedding vectors.

Null saved ranks are interpreted as one position after the candidate list because the known anchor was not present in the saved rank range.
