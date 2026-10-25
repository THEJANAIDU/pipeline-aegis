# Problems this release addresses

Research reviewed 2026-10-25. These are recurring operational concerns, not a statistically ranked survey of engineers.

|Problem|Implementation|Boundary / remaining admin work|
|---|---|---|
|Scanners return success while finding vulnerabilities, or disappear entirely|Normalize results and decide centrally; nonzero exits, malformed JSON, timeouts, parse errors, missing tools and incomplete image coverage are errors|Scanner databases need network access and regular refresh|
|Credentials remain on agents or are exposed to forks|Checkout credentials lint; separate scan job, no app execution, scrub scanner environment|Disable fork secrets and use disposable unprivileged agents; isolate image building|
|Application authors remove security checks|Protected `extends` template and trusted policy/rules|Configure Required template checks and branch protection outside the app repo|
|Broad identities and service connections|Document least privilege, project-scoped token access, WIF and per-pipeline authorization|These are administrative controls; this local scanner does not claim to audit the live tenant|
|Mutable images change after scanning|Agent requires image@sha256:digest|Release pipeline must deploy precisely the scanned digest from the same trusted run|
|Noise and permanent suppressions|Severity policy and exact finding fingerprints; owner/reason/ticket/expiry required, maximum 90 days|Protect policy against app edits; no broad wildcard exemptions|
|Secrets leak from scanner evidence|Generic messages; never publish source snippets, secret matches or raw stdout/stderr|File names, rule IDs and dependency names are retained; protect reports as sensitive artifacts|
|Docker/Kubernetes/ADO mistakes repeated across projects|Local Dockerfile, Kubernetes and pipeline checks plus Trivy IaC analysis|Heuristic lint is not a complete Azure YAML compiler or Helm renderer|
|Approval can be edited out of YAML|Document resource-owner Environment approvals and protected service connection checks|Ops/DevOps must configure checks, disable self approval and restrict bypass rights|

## Primary sources

- [Microsoft: secure Azure Pipelines](https://learn.microsoft.com/en-us/azure/devops/pipelines/security/overview?view=azure-devops) — credential avoidance, untrusted builds, protected resources.
- [Microsoft: security templates](https://learn.microsoft.com/en-us/azure/devops/pipelines/security/templates?view=azure-devops) — includes versus extends and protected templates.
- [Microsoft: approvals and checks](https://learn.microsoft.com/en-us/azure/devops/pipelines/process/approvals?view=azure-devops) — approvals live outside YAML; resource administrators own them.
- [Microsoft: secure repositories and pull requests](https://learn.microsoft.com/en-us/azure/devops/repos/git/secure-repositories-pull-requests) — branch reviews and validation.
- [Microsoft: service connection security](https://microsoft.github.io/code-with-engineering-playbook/CI-CD/dev-sec-ops/azure-devops-service-connection-security/) — authorized pipelines can execute arbitrary commands with a connection.
- [Trivy configuration guidance](https://github.com/aquasecurity/trivy/blob/main/docs/guide/configuration/index.md) — keep gate policy outside application control.
- [Trivy reporting](https://www.trivy.dev/docs/latest/guide/configuration/reporting/) — JSON/SARIF and scanning categories.
- [Semgrep CLI](https://docs.semgrep.dev/cli-reference) — CE scanning behavior, exclusions, parse errors and JSON output.

These informed the design. No customer surveys, live Azure DevOps audit or claim of exhaustive vulnerability coverage was performed.
