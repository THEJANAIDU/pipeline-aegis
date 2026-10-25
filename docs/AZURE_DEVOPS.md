# Azure DevOps adoption

## 1. Establish the security trust boundary

Import this repository as `Platform/pipeline-aegis` (or connect a protected GitHub mirror). Security maintainers own it. Require independent reviews for changes to agent, rules, policy, template and toolchain. Create an immutable protected release tag and replace `refs/tags/v0.1.0` in the example with that tag. Do not give application build identities write access to this repository or release tags.

Create a disposable Linux security agent pool `AegisSecurityEphemeral` with Python 3.10+, Trivy 0.76.1 Semgrep 1.182.1, Ruff 0.14.14 and ShellCheck preinstalled on PATH. Install and verify tools from official releases during image baking; pin image digest and dependency hashes in your organization's image factory. The provided `Dockerfile.toolchain` is a development image recipe; promote only after reviewing its resolved base digest, full dependency lock and scanner licenses. Do not run fork builds on long-lived agents with private network or production credentials.

The template deliberately expects an administered toolchain. Missing scanners fail rather than downloading arbitrary binaries during an app build. Its Python install uses the protected security source and PyPI; replace this with your reviewed wheel/locked internal index for restricted production environments.

## 2. Wire source and image scanning

The image build runs in a separate disposable builder, without production credentials. Scan its exact source revision and push the resulting image into a quarantine registry. Resolve the registry SHA256 digest after the push. Use that digest as the template's `image` parameter; the placeholder is intentionally invalid and will fail.

Copy `templates/azure-pipelines.example.yml` into your application repo and edit the security repository reference, protected release ref and immutable image. The template uses multi-repo checkout to keep application and security source separate, with no persisted credentials. Grant only that pipeline read access to the security repository. Change the `pool.name` in the protected template to your administered pool.

For private registries, supply narrowly scoped short-lived pull authentication to Trivy through an isolated job credential helper. The scanner subprocess receives a scrubbed environment; it does not inherit Azure credentials, System.AccessToken, arbitrary TRIVY_* overrides or SEMGREP_* overrides. For this initial version use public images or explicitly provision an isolated credential file/tool wrapper in the protected toolchain. Do not add passwords to CLI flags or publish raw scanner output.

The example is a scanning template, not an application builder or automatic production deployment. Application build systems vary; integrate the gate into the outer release template maintained by your security team. Keep the image digest and source commit from a single successful build resource run. Never read “latest successful” again after approval. A downstream release must depend on Security success, download only that run's artifact and deploy exactly its digest. The generated JSON is unsigned evidence: JSON validation alone is not a tamper-resistant authorization mechanism.

## 3. Enforce Azure controls (administrator)

1. On deployment service connections, configure a **Required template** check pointing to your protected outer release template. A required scan template alone does not prove an independent release pipeline consumed its result. Restrict authorized pipelines individually; disable open access.
2. Create staging and production Environments. On production, add an **Approval** check for the Ops/DevOps group, disable self approval and set a rejection/expiry policy. Use branch control, required template and exclusive lock checks where appropriate. Limit who can administer or bypass these resources. YAML ManualValidation by itself is insufficient.
3. Use workload identity federation for Azure service connections, scoped to the target resource group/resources. Separate build/pull/deploy identities; application scan jobs receive no deploy role.
4. Enable project-scoped job authorization and Protect access to repositories in YAML pipelines. Authorize only required repos. Avoid broad PATs and collection-scoped identities.
5. In Azure Repos, set required **Build validation** branch policies; a YAML `pr:` trigger is not how Azure Repos PR validation is enforced. Require reviews and reset votes after changes. For GitHub, configure required checks and fork permissions appropriately.
6. Restrict variable groups, secure files, agent pools and registry access to explicit pipelines. Keep secrets in Key Vault or short-lived credentials, not YAML.
7. Keep scan/report artifact retention short, restrict download permissions and enable audit logging. Scan historical Git secrets separately; this release scans the working tree, not history.

## 4. Validate adoption before allowing production

In a nonproduction project, run a vulnerable fixture, a clean reviewed app, an unavailable scanner, a scanner timeout and an unauthorized template change. Verify all invalid cases block. Verify an application contributor cannot remove a production check, access deployment credentials in PR builds, forge another run's evidence or change the approved image. Reject production approval as Ops and confirm no deployment occurs. Complete staging rollout/health checks and rollback rehearsals before promoting an immutable release.

This kit has local tests and scanner acceptance evidence. Tenant permissions, private registries, required-template behavior and actual deployments must be validated in your own Azure DevOps project; no live tenant configuration is implied.

## Release evidence verification

Use `aegis verify-release` inside the protected release template after downloading the exact triggering scan run's artifact. Pass the exact source checkout, intended image digest and protected policy. It rejects stale results (24 hours default), source/image/policy changes, incomplete coverage and blocking findings. If approval takes longer, rescan rather than extending evidence indefinitely. Successful verification does not replace the Ops Environment approval. Never accept an unsigned JSON report supplied by an application contributor as independent proof.
