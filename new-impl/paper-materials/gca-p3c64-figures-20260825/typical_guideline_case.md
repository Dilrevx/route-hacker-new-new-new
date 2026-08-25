# Typical Guideline Case: Attacker-Controlled JNDI Lookup Target

## Paper Use

This case is a compact example for explaining how GCA turns heterogeneous CVE records into a reusable audit guideline. The guideline is not a project signature: it describes a mechanism-level route from attacker-controlled lookup material into JNDI/LDAP/RMI naming APIs without same-path constraints on scheme, authority, object factory, object type, or destination.

## Example Case

| Field | Value |
| --- | --- |
| Identity | `apache__axis-axis1-java::CVE-2023-51441` |
| CVE | `CVE-2023-51441` |
| Guideline ID | `gl_mech_0046` |
| Mechanism ID | `mech_jndi_untrusted_lookup_target` |
| Mechanism name | attacker-controlled JNDI lookup target |

## Released Retrieval Guideline

> Trace attacker-controlled names, URLs, headers, configuration values, or lookup keys into JNDI, LDAP, RMI, naming-context, or remote lookup APIs. Report code paths where the lookup scheme, authority, object factory, object type, and network destination are not constrained before lookup. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 6 historical CVE example(s), not as a project-specific signature. A safe implementation should bind lookup inputs to trusted constants or allowlists, restrict schemes and destinations, and disable remote object factories.

## Why This Is A Good Paper Example

- The CWE labels around the same mechanism are heterogeneous: CWE-502 (7), CWE-20 (6), CWE-184 (3), CWE-74 (3), CWE-918 (2), CWE-99 (1), CWE-470 (1).
- The GCA mechanism appears across refined clusters 15, 26, 27, showing that the reusable mechanism can be recovered even when the surrounding CVE/CWE space is noisy.
- The generated guideline names concrete audit handles: attacker-controlled names/URLs/configuration, JNDI/LDAP/RMI lookup sinks, scheme/destination/object-factory constraints, and same-path guard checking.
- This directly matches the paper narrative: GCA extracts a root-cause mechanism, online retrieval uses the mechanism text as the query, and the downstream auditor receives a focused investigation obligation.

## Mechanism Evidence Summary

| Item | Value |
| --- | --- |
| Active candidate groups | 8 |
| Distinct historical CVEs in candidate groups | 14 |
| Matched mechanism terms | InitialContext.lookup, JNDI lookup, LDAP lookup, jndi, ldap, lookup, object factory, rmi |

## Suggested Figure Caption

GCA converts coarse and inconsistent CVE/CWE labels into mechanism-level audit guidelines. In this example, several historical vulnerabilities with different surrounding labels map to a single actionable mechanism: attacker-controlled JNDI lookup target. The resulting guideline supplies a reusable source-sink-guard obligation for repository-level retrieval and audit.
