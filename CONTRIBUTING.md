# Contributing

Open an issue describing the detection gap, supported language/tool and expected remediation. Add a minimal synthetic fixture, regression tests for both unsafe and safe behavior, and a redaction test if any scanner payload changes. Never use real credentials. Run the tests with Python 3.10 and 3.12. Keep runtime dependencies small and scanners isolated from untrusted application execution.

Security rules, policy and deployment template changes need independent security review. Do not add silent skips, automatic suppression, app-supplied shell commands, auto-install from app manifests or automatic production remediation. Scanner integration changes need real-tool acceptance evidence in addition to mocked contract tests. Contributions are made under Apache-2.0; third-party rule packs must retain their applicable licenses.
