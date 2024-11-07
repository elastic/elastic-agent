param (
    [string]$GROUP_NAME
)

Write-Output "~~~ Receiving ESS stack metadata"

# Retrieve metadata and set environment variables
$env:ELASTICSEARCH_HOST = & buildkite-agent meta-data get "es.host"
$env:ELASTICSEARCH_USERNAME = & buildkite-agent meta-data get "es.username"
$env:ELASTICSEARCH_PASSWORD = & buildkite-agent meta-data get "es.pwd"
$env:KIBANA_HOST = & buildkite-agent meta-data get "kibana.host"
$env:KIBANA_USERNAME = & buildkite-agent meta-data get "kibana.username"
$env:KIBANA_PASSWORD = & buildkite-agent meta-data get "kibana.pwd"

Write-Output "~~~ Running integration tests as $env:USERNAME"
Write-Output "~~~ Integration tests: $GROUP_NAME"

# Check gotestsum version
# $Env:PATH
# go env
# TODO: add to the image
$Env:PATH += ";C:\Users\Buildkite\.go\go-1.22.8\bin"
go install gotest.tools/gotestsum@latest
# tree "C:\Users\Buildkite\.go\go-1.22.8\packages\bin"
gotestsum --version

# Read package version from .package-version file
$PACKAGE_VERSION = Get-Content .package-version -ErrorAction SilentlyContinue
if ($PACKAGE_VERSION) {
    $PACKAGE_VERSION = "${PACKAGE_VERSION}-SNAPSHOT"
}

echo "~~~ Building test binaries"
& mage build:testBinaries

# Run integration tests with gotestsum
echo "~~~ Running tests"
$env:TEST_BINARY_NAME = "elastic-agent"
$env:AGENT_VERSION = $PACKAGE_VERSION
$env:SNAPSHOT = $true

# Error handling setup for gotestsum execution
$ErrorActionPreference = 'Continue'
& gotestsum --no-color -f standard-quiet --junitfile "build/${GROUP_NAME}.integration.xml" --jsonfile "build/${GROUP_NAME}.integration.out.json" --% -tags integration -test.shuffle on -test.timeout 2h0m0s github.com/elastic/elastic-agent/testing/integration -v -args "-integration.groups=$GROUP_NAME" "-integration.sudo=true"
$TESTS_EXIT_STATUS = $LASTEXITCODE
$ErrorActionPreference = 'Stop'

# Generate HTML report if XML output exists
$outputXML = "build/${GROUP_NAME}.integration.xml"
if (Test-Path $outputXML) {
    # Install junit2html if not installed
    go install github.com/alexec/junit2html@latest
    Get-Content $outputXML | junit2html > "build/TEST-report.html"
} else {
    Write-Output "Cannot generate HTML test report: $outputXML not found"
}

# Exit with the test exit status
exit $TESTS_EXIT_STATUS
