# Developer Guide for the Integration and E2E Testing Framework

## Prerequisites

### Dependencies

Go version should be at least the same than the one in [.go-version](https://github.com/elastic/elastic-agent/blob/main/.go-version) file at the root of this repository

[GCloud CLI](https://cloud.google.com/sdk/gcloud)

### Configuration

ESS (QA) API Key to create on https://console.qa.cld.elstc.co/deployment-features/keys

Warning: if you never created a deployment on it, you won't have permission to get this key so you will need to create one first.

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

#### Passing additional go test flags

When running the tests we can pass additional go test flag using the env variable `GOTEST_FLAGS`.

These flags are passed also when calculating batches for remote execution of integration tests.
This allows for selecting a subset of test in a convenient way (see examples below)

This feature is intended mostly for integration tests debugging/development without the need for
new mage targets corresponding to a new set of test flags.

A few examples:

##### Run a single test with an exact match
We want to run only the test named "TestStandaloneUpgrade"
`GOTEST_FLAGS="-test.run ^TestStandaloneUpgrade$" mage integration:test`

##### Run a tests matching a partial expression
We want to run any test with "Upgrade" in the name
`GOTEST_FLAGS="-test.run Upgrade" mage integration:test`

##### Run a single test and signal that we want the short version
We pass a `-test.short` flag along with the name match
`GOTEST_FLAGS="-test.run ^TestStandaloneUpgrade$ -test.short" mage integration:test`

##### Run a single test multiple times
We pass a `-test.count` flag along with the name match
`GOTEST_FLAGS="-test.run ^TestStandaloneUpgrade$ -test.count 10" mage integration:test`

##### Run specific tests
We pass a `-test.run` flag along with the names of the tests we want to run in OR
`GOTEST_FLAGS="-test.run ^(TestStandaloneUpgrade|TestFleetManagedUpgrade)$" mage integration:test`

##### Limitations
Due to the way the parameters are passed to `devtools.GoTest` the value of the environment variable
is split on space, so not all combination of flags and their values may be correctly split.

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

### Test namespaces

Every test has access to its own unique namespace (a string value). This namespace can
be accessed from the `info.Namespace` field, where `info` is the struct value returned
from the `define.Require(...)` call made at the start of the test.

Namespaces should be used whenever test data is being written to or read from a persistent store that's
shared across all tests. Most commonly, this store will be the Elasticsearch cluster that Agent
components may index their data into. All tests share a single stack deployment and, therefore,
a single Elasticsearch cluster as well.

Some examples of where namespaces should be used:
* When creating a policy in Fleet. The Create Policy and Update Policy APIs takes a namespace parameter.
* When searching for documents in `logs-*` or `metrics-*` data streams. Every document in these
  data streams has a `data_stream.namespace` field.

:warning: Not using namespaces when accessing data in a shared persistent store can cause tests to
be flaky.

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

### Using a different agent version from the stack version

The agent version is used as a fallback for the stack version to use in integration tests
if no other version is specified.

If we need to use a different version between agent and stack we can specify the stack version
using a separate env variable `AGENT_STACK_VERSION` like in this example (we used a
custom package version for the agent):

```AGENT_VERSION="8.10.0-testpkgversion.1-SNAPSHOT" AGENT_STACK_VERSION="8.10.0-SNAPSHOT" mage integration:test```
