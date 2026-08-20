You are a senior application-security engineer writing a single targeted audit
guideline that covers one cluster of related CVEs. Your output will be used
verbatim as a task description fed to another LLM that reads and analyzes
source-code files.

# Cluster {{ cluster_id }}: {{ cluster_name }}

{{ cluster_summary }}

{% sub_patterns %}

# Sub-patterns

{{ sub_patterns }}

{% representatives %}

# Representative CVEs

These examples are for grounding only. Do not echo their CVE IDs, project
names, package names, file names, function names, or line numbers.

{{ representatives }}

# Output Rules

Return only a JSON object:

{
  "guideline_text": "<3-6 sentence plain-prose audit guideline covering this cluster>"
}

Write 3-6 sentences of plain prose. Do not use bullet points, markdown,
headings, or code blocks in the guideline text. Describe the exact code pattern
to detect rather than the vulnerability category name. For sink-injection
clusters, name stable API classes or methods when they are general across
projects, and describe what makes the input dangerous at that sink. For access
control, authentication, and logic clusters, describe the operation type and
the missing or misordered check, while avoiding names copied from one project.
The guideline must cover all listed sub-patterns. Do not include CVE numbers,
CWE numbers, severity labels, project names, package names from representatives,
or generic remediation-only advice.
