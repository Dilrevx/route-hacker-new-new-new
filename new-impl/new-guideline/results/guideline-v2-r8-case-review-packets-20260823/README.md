# Guideline Case Review Packets

These packets make the boundary repair pack actionable at reviewer level.
They are review-only and do not change released guidelines, lexicon entries, sidecars, ranking, or audit prompts.

- Packet count: 8

| Packet | Guideline | Mechanism | Repair Kind | Strong | Weak | Missing |
| --- | --- | --- | --- | ---: | ---: | ---: |
| [packets/01-gl_mech_0001.md](packets/01-gl_mech_0001.md) | `gl_mech_0001` | `mech_temp_file_delete_mkdir_race` | `split_mechanism_boundary` | 3 | 2 | 0 |
| [packets/02-gl_mech_0022.md](packets/02-gl_mech_0022.md) | `gl_mech_0022` | `mech_xml_external_entity_resolution` | `split_mechanism_boundary` | 1 | 1 | 3 |
| [packets/03-gl_mech_0116.md](packets/03-gl_mech_0116.md) | `gl_mech_0116` | `mech_ssrf_redirect_following_client` | `split_mechanism_boundary` | 2 | 3 | 0 |
| [packets/04-gl_mech_0007.md](packets/04-gl_mech_0007.md) | `gl_mech_0007` | `mech_ssrf_webhook_url_fetch` | `revise_mechanism_text_from_evidence` | 0 | 1 | 0 |
| [packets/05-gl_mech_0011.md](packets/05-gl_mech_0011.md) | `gl_mech_0011` | `mech_path_traversal_missing_canonical_prefix` | `revise_mechanism_text_from_evidence` | 2 | 3 | 1 |
| [packets/06-gl_mech_0015.md](packets/06-gl_mech_0015.md) | `gl_mech_0015` | `mech_temp_file_delete_mkdir_race` | `revise_mechanism_text_from_evidence` | 0 | 1 | 0 |
| [packets/07-gl_mech_0061.md](packets/07-gl_mech_0061.md) | `gl_mech_0061` | `mech_open_redirect_unsafe_uri_scheme` | `revise_mechanism_text_from_evidence` | 3 | 2 | 0 |
| [packets/08-gl_mech_0117.md](packets/08-gl_mech_0117.md) | `gl_mech_0117` | `mech_ssrf_webhook_url_fetch` | `revise_mechanism_text_from_evidence` | 2 | 3 | 0 |

## Use Policy

- Fill the evidence fields after checking old-side source and patch/fix semantics.
- Do not treat an unfilled packet as a release-ready guideline change.
- Keep semantic guideline decisions separate from same-identity recall metrics.
