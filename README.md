# Pipeline Aegis

An open source security agent for Azure DevOps: scan application code, dependencies, secrets, infrastructure and the exact container image before deployment. Apache-2.0 licensed. No LLM account or paid security subscription required for the included local checks.

**Status: tested MVP, not a production security certification.** It detects risks and gates a pipeline; it does not automatically repair application code or change Azure permissions. The included application rules target Python and JavaScript/TypeScript. Extend reviewed rules for your languages and frameworks before treating SAST coverage as sufficient.

## What it does

|Layer|Checks|
|---|---|
|Application|Semgrep CE with four curated starter rules: unsafe Python subprocess/deserialization/TLS and JavaScript eval|
|Advanced lint|Ruff E/F/B/S rules for Python; ShellCheck for `.sh` and `.bash`; required when those files exist|
|Supply chain|Trivy working-tree dependency vulnerabilities, secrets and IaC misconfiguration|
|Container|Trivy scans a required immutable registry image; Dockerfile root, credential and remote-script lint|
|Azure DevOps YAML|Persisted credentials, ignored errors, unsafe deployment conditions, unversioned tasks and unsafe script patterns|
|Kubernetes YAML|Privileged execution, root containers, host networking and mutable image references|
|Gate|HIGH/CRITICAL and unknown severity block by default; missing/failed/incomplete scanners error|
|Triage|Redacted JSON, Markdown and SARIF; exact finding exceptions require owner/reason/ticket/expiry ≤90 days|

Local lint checks are heuristic and explain their remediation. Trivy supplies broader IaC scanning. This is not a full Azure YAML compiler, a Helm template renderer, a DAST engine, malware detection, historical Git secret scanning, license policy engine, signing service or runtime protection product. Secrets discovered in current files must still be revoked and removed from history.

## Start locally (macOS/Linux)

Use Python 3.10 or later. Install Trivy 0.76.1 and Semgrep 1.182.1 from official releases using your approved tool manager; install ShellCheck if your project contains shell scripts. Docker is not required by the Python CLI; Trivy can pull the registry image directly.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install . semgrep==1.182.1 ruff==0.14.14
# Confirm tools exist before scanning:
trivy --version
semgrep --version
ruff --version
shellcheck --version
# Keep reports outside the source directory:
aegis scan --repo /absolute/path/to/application \
  --image 'registry.example/team/app@sha256:REPLACE_WITH_REAL_64_HEX_DIGEST' \
  --policy /absolute/path/to/protected-security-repo/policy.json \
  --output /absolute/path/to/security-reports
```

Replace the image placeholder with the registry digest of the artifact you intend to deploy. For a first local look without scanner installation:

```sh
aegis scan --repo /absolute/path/to/application \
  --output /absolute/path/to/security-reports --lint-only
```

Lint-only always returns **2**: it provides feedback but cannot approve deployment. Full scans without an image also return 2. Windows users can use WSL2 or the development Docker image; native Windows scanner compatibility has not been validated.

Exit codes: **0 passed**, **1 blocking findings**, **2 configuration, execution, coverage or reporting error**. Only zero may permit a downstream stage. Reports contain generic remediation messages and locations, never raw scanner snippets or secret matches. Treat report metadata as sensitive.

## Use the container toolchain

```sh
docker build -f Dockerfile.toolchain -t pipeline-aegis:dev .
mkdir -p /tmp/aegis-reports
# The container runs as UID 10001: make only this report directory writable to that UID.
# On Linux, arrange ownership with your administrator rather than chmod 777.
docker run --rm \
  --cap-drop ALL --security-opt no-new-privileges \
  -v /absolute/path/to/application:/source:ro \
  -v /tmp/aegis-reports:/reports \
  pipeline-aegis:dev scan --repo /source \
  --image 'registry.example/team/app@sha256:REPLACE_WITH_REAL_64_HEX_DIGEST' \
  --output /reports
```

The development recipe pins scanner releases and the Trivy base digest. Its Python base, OS packages and transitive pip dependencies still need a reviewed image-factory lock before production use. Do not mount the Docker socket. Do not give the scan job production credentials. Private registry authentication needs an explicitly reviewed pull-only credential integration; the current template does not configure it automatically.

## Azure DevOps setup

Read [the adoption guide](docs/AZURE_DEVOPS.md), then customize [the example](templates/azure-pipelines.example.yml) and [protected scan template](templates/security.yml). The template expects an administered **AegisSecurityEphemeral** pool with scanners installed. Missing tools intentionally block.

The security repo and policy must be outside application-author control. Required template checks, Ops/DevOps Environment approvals, branch policies and service connection permissions must be administered outside application YAML. The scan template alone does not prove that a separate release pipeline used its result: your protected outer release template must bind a successful scan to the same run, source revision and immutable image digest. No automatic production deployment is included.

## Exceptions

Find the finding's `fingerprint` in `report.json`, then propose a reviewed change to protected `policy.json`:

```json
{
  "block_severities": ["HIGH", "CRITICAL"],
  "exceptions": [{
    "fingerprint": "REPLACE_WITH_64_HEX_FINGERPRINT",
    "owner": "platform-security",
    "reason": "Compensating control reviewed",
    "ticket": "SEC-123",
    "expires": "YYYY-MM-DD"
  }]
}
```

Expired/invalid exceptions fail the gate. A fingerprint includes tool, rule, file and line; moving code can invalidate the exception. Application `.semgrepignore` files and inline Trivy suppressions block pending security review. Git ignores and `nosemgrep` comments cannot silently suppress these scans. This is conservative: review false positives in the protected policy rather than blanket skipping source directories.

## Development and evidence

```sh
python -m pip install . -r REQUIREMENTS-DEV.txt
python -m pytest tests -q
```

The adapter contract tests use controlled scanner responses and do not prove vulnerability database coverage. See [verification](docs/VERIFICATION.md) for actual scanner acceptance evidence and limitations. [Research and problem mapping](docs/RESEARCH.md) explains the Azure DevOps concerns behind the implementation. [Security model](SECURITY.md) documents trust assumptions.

Contributions: add a failing fixture and regression test for each rule/adapter; keep source snippets and credentials out of results; never downgrade execution errors to successful scans. Follow the [contribution guide](CONTRIBUTING.md).

## Verify evidence before a release

In a protected release job, download evidence from the **same successful scan run** (not an app-provided file), checkout the exact source and invoke:

```sh
aegis verify-release --report /trusted/run-artifacts/report.json \
  --repo /absolute/path/to/exact-source-checkout \
  --image 'registry.example/team/app@sha256:REPLACE_WITH_REAL_64_HEX_DIGEST' \
  --policy /protected/security/policy.json --max-age-hours 24
```

This rejects changed source, image, policy, stale evidence, incomplete coverage and blocking findings. The source-tree hash is content-based and excludes documented dependency/cache directories. It does not verify a signature or the trustworthiness of an artifact's origin. Ops approval and protected artifact/run access remain mandatory.

For a deliberately unsafe local demo, scan `examples/unsafe` with reports in a sibling directory. A full scan should block; lint-only returns incomplete coverage. Never deploy this fixture.
