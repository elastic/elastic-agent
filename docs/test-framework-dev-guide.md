# Developer Guide for the Integration and E2E Testing Framework

## Prerequisites

### Dependencies

Go version should be at least the same than the one in [.go-version](https://github.com/elastic/elastic-agent/blob/main/.go-version) file at the root of this repository

[GCloud CLI](https://cloud.google.com/sdk/gcloud)

### Configuration

ESS (QA) API Key to create on https://console.qa.cld.elstc.co/deployment-features/keys

Warning: if you never created a deployment on it, you won't have permission to get this key so you will need to create one first.

## Writing tests

Write integration and E2E tests by adding them to the `testing/integration`
folder.

// TODO: Replace with a comprehensive write up of `define.*` directives,
// environment variables, etc. useful when writing tests. Until then...

Look at existing tests under the `testing/integration` for examples of how
to write tests using the integration and E2E testing framework. Also look at
the `github.com/elastic/elastic-agent/pkg/testing/define` package for the test
framework's API and the `github.com/elastic/elastic-agent/pkg/testing/tools`
package for helper utilities.

## Running tests

Some one-time setup is required to run any integration and E2E tests. Run
`mage integration:auth` to perform this setup.

Some integration and E2E tests are safe to run locally. These tests set
`Local: true` in their test functions' `define.Require` directive. Tests that
don't set `Local: true` or explicitly set `Local: false` are not considered
safe to run locally and will be executed on remote VMs instead.

Run `mage integration:test` to execute all tests under the `testing/integration`
folder. All tests are executed on remote VMs, including those that set `Local: true`.

Run `mage integration:local` to execute only those tests under the
`testing/integration` folder that set `Local: true`. These tests are executed
on your local machine.

Run `mage integration:single [testName]` to execute a single test under the `testing/integration` folder. Only the selected test will be executed on remote VMs.

Run `mage integration:matrix` to run all tests on the complete matrix of supported operating systems and architectures of the Elastic Agent.

## Troubleshooting Tips

### Error: GCE service token missing; run 'mage integration:auth'
If you encounter this error when running `mage integration:test`, it's because
the test runner is unable to create VMs on GCP to execute the tests.

As the error message suggests, run `mage integration:auth` to resolve this error.

### Error: missing required Elastic Agent package builds for integration runner to execute: ...
If you encounter this error when running `mage integration:test` or
`mage integration:local`, it's because the test runner couldn't find the appropriate
Agent packages in the `build/distributions` folder.

Run `mage package` with the appropriate value(s) in `PLATFORMS`, as suggested by the
error message, to build the necessary Agent packages first.

If the issue is that the built Agent packages contain `-SNAPSHOT` in their versions,
whereas the package names in the error message do not, either omit `SNAPSHOT=true` from
the `mage package` command OR set the `AGENT_VERSION` environment variable to a version
that includes the `-SNAPSHOT` suffix when running `mage integration:test` or
`mage integration:local`.

### OGC-related errors
If you encounter any errors mentioning `ogc`, try running `mage integration:clean` and then
re-running whatever `mage integration:*` target you were trying to run originally when you
encountered the error.
