# Security reporting
Do not publish credentials or exploit details in public issues. Contact the repository owner privately using GitHub private vulnerability reporting (enable it before accepting reports). Rotate exposed credentials immediately. This agent detects a subset of risks and does not establish that an application is secure.

## Trust model
Run scanning on disposable agents with no cloud credentials, no Docker socket exposed to untrusted code, and a read-only source checkout. The agent never executes application code, dependency install scripts, Docker builds, pipeline scripts, or remediation commands. Scanner parsers still process hostile input: sandbox them and keep them patched. Do not run untrusted PRs on privileged self-hosted production agents.

Security policy, scanner binaries, Semgrep rules, templates and exceptions must come from a separately protected security repository/revision. The scanned repository must not be allowed to replace them. Results are evidence, not signed attestations. An attacker who controls the agent or report storage can forge results. External approval and protected resource checks are required for deployment authorization.
