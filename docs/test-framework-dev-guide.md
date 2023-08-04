# Developer Guide for the Integration and E2E Testing Framework

## Prerequisites

### Dependencies

Go version should be at least the same than the one in [.go-version](https://github.com/elastic/elastic-agent/blob/main/.go-version) file at the root of this repository

[GCloud CLI](https://cloud.google.com/sdk/gcloud)

### Configuration

ESS (QA) API Key to create on https://console.qa.cld.elstc.co/deployment-features/keys

Warning: if you never created a deployment on it, you won't have permission to get this key, so you will need to create one first.

## Running tests

Some integration and E2E tests are safe to run locally. These tests set
`Local: true` in their test functions' `define.Require` directive. Tests that
don't set `Local: true` or explicitly set `Local: false` are not considered
safe to run locally and will be executed on remote VMs instead.

The framework will look for the agent version defined by the `AGENT_VERSION`
environment variable, even for local tests, **regardless of what was defined in
the test Fixture**. If `AGENT_VERSION` isn't set, it'll default to the current
version without SNAPSHOT.

### Setup
One-time setup is required to run any integration and E2E tests. Run
`mage integration:auth` to perform this setup.

### Running the tests

The test are run with mage using the `integration` namespace:

- `mage integration:test` to execute all tests under the `testing/integration`
  folder. All tests are executed on remote VMs, including those that set `Local: true`.

- `mage integration:local [testName|all]` to execute only those tests under the
  `testing/integration` folder that set `Local: true`. It'll run all the tests if
  `all` is passed as argument, or it'll pass `[testName]` to `go test` as
- `--run=[testName]`.These tests are executed on your local machine.

- `mage integration:local [testName]` same as `mage integration:local`, but it'll
  pass `[testName]` to `go test` as `--run=[testName]`.

- `mage integration:single [testName]` to execute a single test under the `testing/integration` folder. Only the selected test will be executed on remote VMs.

- `mage integration:matrix` to run all tests on the complete matrix of supported operating systems and architectures of the Elastic Agent.

#### Selecting specific platform

By default, the runner will deploy to every combination of operating system and architecture that the tests define
as supporting. When working on tests and debugging an issue it's better to limit the operating system and architecture
to a specific one. This can be done inside a test but requires the test code to be modified. An easier way is available
using the `TEST_PLATFORMS="linux/amd64"` environment variable. This variable can take multiple definitions with a space
between, and it can be very specific or not very specific.

- `TEST_PLATFORMS="linux" mage integration:test` to execute tests only on Linux using both AMD64 and ARM64.
- `TEST_PLATFORMS="linux/amd64" mage integration:test` to execute tests only on Linux AMD64.
- `TEST_PLATFORMS="linux/arm64/ubuntu mage integration:test` to execute tests only on Ubuntu ARM64.
- `TEST_PLATFORMS="linux/amd64/ubuntu/20.04 mage integration:test` to execute tests only on Ubuntu 20.04 ARM64.
- `TEST_PLATFORMS="windows/amd64/2022 mage integration:test` to execute tests only on Windows Server 2022.
- `TEST_PLATFORMS="linux/amd64 windows/amd64/2022 mage integration:test` to execute tests on Linux AMD64 and Windows Server 2022.

> **_NOTE:_**  This only filters down the tests based on the platform. It will not execute a tests on a platform unless
> the test defines as supporting it.

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

### Cleaning up resources

The test run will keep provisioned resources (instances and stacks) around after the tests have been ran. This allows
following `mage integration:*` commands to re-use the already provisioned resources.

- `mage integration:clean` will de-provision the allocated resources and cleanup any local state.

Tests with external dependencies might need more environment variables to be set
when running them manually, such as `ELASTICSEARCH_HOST`, `ELASTICSEARCH_USERNAME`,
`ELASTICSEARCH_PASSWORD`, `KIBANA_HOST`, `KIBANA_USERNAME`, and `KIBANA_PASSWORD`.

### Debugging tests

#### Auto diagnostics retrieval
When an integration test fails the testing fixture will try its best to automatically collect the diagnostic
information of the installed Elastic Agent. In the case that diagnostics is collected the test runner will
automatically transfer any collected diagnostics from the instance back to the running host. The results of the
diagnostic collection are placed in `build/diagnostics`.

#### Gather diagnostics manually
In the case that you want to run the integration testing suite and have it gather the diagnostics at the end of
every tests you can use the environment variable `AGENT_COLLECT_DIAG=true`. When that environment variable is defined
it will cause the testing fixture to always collect diagnostics before the uninstall in the cleanup step of a test.

#### Keeping Elastic Agent installed
When the testing fixture installs the Elastic Agent it will automatically uninstall the Elastic Agent during the
cleanup process of the test. In the case that you do not want that to happen you can disable the auto-uninstallation
using `AGENT_KEEP_INSTALLED=true` environment variable. It is recommend to only do this when inspecting a single test.

- `AGENT_KEEP_INSTALLED=true mage integration:single [testName]`

## Manually running the tests

If you want to run the tests manually, skipping the test runner, set the
`TEST_DEFINE_PREFIX` environment variable to any value and run your tests normally
with `go test`. E.g.:

```shell
TEST_DEFINE_PREFIX=gambiarra go test -v -tags integration -run TestProxyURL ./testing/integration/
```

## Writing tests

Write integration and E2E tests by adding them to the `testing/integration`
folder.

// TODO: Replace with a comprehensive write-up of `define.*` directives,
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

### Failures on reused resources
The integration framework tries to re-use resource when it can. This improves the speed at
which the tests can run, but also means its possible for a failed test to leave state behind
that can break future runs.

Run `mage integration:clean` before running `mage integration:test` to ensure the tests are
being run with fresh instances and stack.

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
