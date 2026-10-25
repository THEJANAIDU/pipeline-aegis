# How the agent works

The CLI is a deterministic policy agent, without an LLM or external model API. It reads source; it never builds or executes the application.

1. Validate trusted policy and output location; hash the source tree. Symlink/special-file sources require a reviewed materialization step before scanning.
2. Run local pipeline/Docker/Kubernetes lint, detecting unsafe patterns and application-controlled scanner suppressions.
3. Run Semgrep with protected starter rules; run Trivy against files and the digest-pinned registry image. Run Ruff for Python and ShellCheck for shell sources. Each process uses argument arrays, a bounded timeout, separate working directory and scrubbed environment. Application config cannot override the gate's severity policy. Local source/config changes during scanning block approval.
4. Validate scanner JSON contracts, map severities, discard raw snippets/messages, and generate stable finding fingerprints. Invalid JSON, unsupported schemas, parser errors, missing executables and scanner failures remain operational errors.
5. Apply reviewed, expiring, exact-fingerprint exceptions. Compute a decision; unknown severities block. Exit nonzero for findings or incomplete coverage.
6. Atomically write private JSON, Markdown and SARIF. Include source-tree SHA256, image digest and policy hash. These hashes aid traceability; they do not cryptographically attest execution or authenticate a report.

Azure DevOps must supply the outer trust boundary: protected security source and toolchain, explicit resource authorization, enforced template, review policies, immutable artifact/run linkage and Ops-controlled approval. Source hashes exclude `.git`, `.venv`, `node_modules`, Python caches and the reserved `aegis-results` directory. Do not store application source inside reserved dependency/cache directories. Repositories using submodules must initialize and materialize reviewed source before scanning. Git history and code hidden inside downloaded dependencies need separate controls.

The security job has no arbitrary stepList injection, no deployment connection and no application-defined installation hooks. Application building, staging deployment and rollback happen in separately protected jobs. Keep scanners up to date; a parser vulnerability still matters when scanning hostile code.
