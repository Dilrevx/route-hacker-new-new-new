# route-hacker-new

Clean new implementation workspace for Route-Hacker experiments.

Current main module: `new-impl/guideline-agent-pipeline/` contains the
guideline-conditioned recall and audit pipeline.

## Execution Note

Use `bobo5090` for remote source materialization, embedding services, and
recall jobs. Do not use `bobo5090` as the LLM audit provider host. Its AI
provider paths are currently considered unavailable for this project: Codex /
TraeX / direct provider calls from that host timed out for both
`DeepSeek-V4-Pro` and `DeepSeek-V4-Flash`.

Run the audit stage from the local development machine instead, using the local
Codex or TraeX login and model access. Known intended audit models include
`DeepSeek-V4-Pro`, `GPT-5.5`, or another locally available model configured in
the local Codex/TraeX provider stack. Keep `bobo5090` as the recall/embedding
host, then mount or copy the recall artifacts for local audit execution.
