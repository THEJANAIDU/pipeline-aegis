# Verification record

Date: 2026-10-25. This is local and GitHub CI acceptance, not a live Azure DevOps production deployment.

## Regression and publication

24 regression tests pass locally on Python 3.12.14. The same suite passed GitHub CI on Python 3.10 and 3.12: [successful run 40219197318](https://github.com/THEJANAIDU/pipeline-aegis/actions/runs/40219197318), source commit `30b2c7e202bbff1ba3d4daeb778a4e4ec260bb13`. All 27 published source files were fetched at that commit and compared byte-for-byte with the source manifest.

Tests cover unsafe pipeline/Docker/Kubernetes rules, malformed YAML, scanner parsing and failures, timeouts, missing tools, redaction, expiring exact exceptions, immutable image references, incomplete coverage, environment scrubbing, suppressions, source binding, report permissions and release evidence changes/staleness. A regression verifies that Ruff unreadable-file and syntax errors cannot pass as ordinary nonblocking lint.

## Real scanner acceptance

Development Docker toolchain built successfully for Linux ARM64 and ran as UID 10001 with all capabilities dropped and no-new-privileges. Tools: Trivy 0.76.1, Semgrep 1.182.1, Ruff 0.14.14, ShellCheck 0.10.0. The agent did not execute the application or shell fixtures.

|Final scenario|Result|Findings|Operational errors|
|---|---|---|---|
|Minimal clean Python source plus immutable hello-world image|Passed, exit 0|0|0|
|Same-run release evidence verification|Passed, exit 0|—|0|
|Unsafe Python, root Dockerfile, shell fixture plus immutable Caddy image|Blocked, exit 1|267|0|

Clean image: `hello-world@sha256:11a3eb1597e864c51b3f56733cb2e8a90bf0c284bfc05f9444d81c558bc848aa`.

Unsafe acceptance image: `caddy@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d`. Final findings: local lint 2, Semgrep 2, Trivy 259 and Ruff 4. ShellCheck also completed successfully on the supplied shell fixture. These counts are a vulnerability-database snapshot, not a lasting assessment of an upstream project. Neither image was deployed.

A separate native Semgrep run on macOS ARM64 detected both intentional unsafe Python patterns. The official Trivy macOS release checksum was verified: `11a9b6cd2752011b54f01ea4bd0dbfa9f0c41dc6538d5a3f9d23955f471bf4e5`.

Python source and wheel distributions build successfully with packaged rules. Local `pip check` reports no broken dependencies. Acceptance input archives were generated without macOS AppleDouble metadata; unreadable input now correctly produces an operational error.

## Boundaries

Live Azure DevOps permissions, administered pools, cross-repo authorization, private registry authentication, protected-template enforcement, Ops approval behavior, real rollout and actual downstream release consumption have not been exercised in a customer tenant. Windows native execution is not tested. The included Semgrep rules are a starter set for Python and JavaScript/TypeScript, not exhaustive application or framework coverage.

A passing scan means this policy passed, not that the app is secure. Working-tree scans do not scan Git history. Source/report hashes do not authenticate unsigned evidence. Protect artifacts and enforce production approval outside application YAML. Threat modeling, manual review, DAST and runtime monitoring remain separate controls.
