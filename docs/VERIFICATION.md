# Verification record

Date: 2026-10-25. This record describes local acceptance, not a live Azure DevOps production deployment.

## Regression tests

24 tests pass on Python 3.12.14. They cover unsafe pipeline/Docker/Kubernetes rules, malformed YAML, scanner parsing and failure, timeouts, missing executables, secret redaction, policy expiry and exact exemptions, immutable image validation, lint-only/incomplete coverage gates, environment scrubbing, suppression detection, source binding, report permissions, release evidence changes/staleness and parent-stage deployment conditions. Scanner responses in contract tests are mocked; see real-tool acceptance below.

A GitHub Actions matrix is included for Python 3.10 and 3.12. Its remote outcome is recorded separately after publication; inclusion of a workflow is not proof that it ran.

## Real tools

- Semgrep 1.182.1 on macOS ARM64 detected both deliberate unsafe Python patterns (shell execution and disabled TLS verification).
- Ruff 0.14.14 detected unsafe Python code and lint issues in the fixture.
- Official Trivy 0.76.1 macOS download SHA256 was checked against the release checksum: `11a9b6cd2752011b54f01ea4bd0dbfa9f0c41dc6538d5a3f9d23955f471bf4e5`.
- Development Docker toolchain built successfully for Linux ARM64, runs as UID 10001, and includes Trivy 0.76.1, Semgrep 1.182.1, Ruff 0.14.14 and ShellCheck 0.10.0.
- Initial full unsafe acceptance completed every requested scanner with zero operational errors, returned exit 1 and **blocked**: local lint 2 findings, Semgrep 2, Trivy 259, Ruff 5, ShellCheck 2 (270 total). The fixture contained Python, shell and a Dockerfile; the scanned image was `caddy@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d`. Findings are a database-dependent snapshot, not a lasting assessment of that upstream project. Caddy was only an acceptance target; no workload was deployed.
- Python source and wheel distributions build successfully, including the packaged Semgrep rules. `pip check` reports no broken dependencies in the local test environment.

## Not validated

Live Azure DevOps permissions, hosted/self-hosted pool setup, cross-repo authorization, private registry authentication, protected template enforcement, Ops group approval behavior, production rollout and actual release consumption have not been exercised against a customer tenant. Windows native execution is not tested. The included Semgrep rules are a starter set; no claim of exhaustive code security, framework coverage or compliance is made. SAST plus SCA does not replace threat modeling, security review, dynamic testing or runtime monitoring.
