<!--
Label this PR with its type: Bug, Enhancement, Breaking change, Deprecation, Cleanup, or Docs.
Add a changelog fragment for user-visible changes (https://github.com/elastic/elastic-agent#changelog) or use the skip-changelog label.
-->

## Related issues

<!-- e.g. Closes #123, Relates #123 -->
-

## Risk

<!-- Select exactly one. If unsure, pick the higher level. -->

- [ ] **Low**: isolated change, no effect on Fleet connectivity, policy handling, or upgrades
- [ ] **Medium**: changes existing behavior, but is feature flagged or a failure does not affect Fleet connectivity, policy handling, or upgrades
- [ ] **High**: touches Fleet connectivity, policy application, upgrade/rollback, installation, or changes defaults for existing users

## Rationale

<!--
What problem does this solve, and why this approach?
Call out any disruption to existing users and how they can mitigate it.
-->

## Rollout and safety

<!--
If this change fails or hits an unexpected state (timeouts, unbounded retries, partial application, invalid configuration,
a component crashing or hanging), the agent must stay connected to Fleet and still be able to receive
a new policy or upgrade to another version. Describe how failures are contained.

New features should be behind a configuration flag that can safely disable them if the unexpected happens.
Name the flag and its default. Consider whether the flag needs to be part of our generally available user
facing configuration, following the guidance below:
- Use `agent.features.*` for configuration that is user facing and must be passed through to supervised components.
- Use `agent.*` for configuration that is user facing but applies only to Elastic Agent itself.
- Use `agent.internal.*` for internal engineering configuration that can be deprecated and removed as needed.

Is downgrading to the previous version safe? Failed upgrades roll back automatically, so call out any
persisted state, config, or on-disk changes the previous version can't read.

Is the existing content of the diagnostics bundle enough to diagnose failures in the field?

Write "N/A" with a reason if this does not apply
-->

## Testing

<!--
Automated coverage (unit, integration) and how a reviewer can verify locally. Note which of the following
apply and what was tested:

- Platforms and packages: Linux/Windows/macOS (amd64/arm64); .tar.gz, .zip, .rpm, .deb, .msi; containers, Kubernetes, and Helm.
- Deployment modes: standalone, Fleet managed, unprivileged, behind a network proxy, air gapped, FIPS compatible.
- Lifecycle: upgrade from previous versions and rollback, restart/reboot, re-enroll, policy reassignment, unenroll, and uninstall.
- Interactions with Elastic Defend (endpoint-security) and tamper protection.

Provide evidence (screenshots, logs, diagnostics) for behavior changes where needed.
-->

<!-- CI Cheatsheet
Trigger comments:
/test             (Or `buildkite test this|it`) Triggers unit test pipeline
/test extended    (Or `buildkite test extended`) Triggers integration test pipeline

PR labels:
skip-ci           Skips unit and integration tests
skip-it           Skips integration tests
-->
