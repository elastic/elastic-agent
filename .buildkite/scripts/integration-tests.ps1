param (
    [string]$GROUP_NAME
    [string]$TEST_SUDO
)

Write-Output "~~~ Switching to PowerShell 7"
pwsh
$PSVersionTable.PSVersion

# TODO: dedicated ESS strack for retries
Write-Output "~~~ Receiving ESS stack metadata"
$env:ELASTICSEARCH_HOST = (buildkite-agent meta-data get "es.host")
$env:ELASTICSEARCH_USERNAME = (buildkite-agent meta-data get "es.username")
$env:ELASTICSEARCH_PASSWORD = (buildkite-agent meta-data get "es.pwd")
$env:KIBANA_HOST = (buildkite-agent meta-data get "kibana.host")
$env:KIBANA_USERNAME = (buildkite-agent meta-data get "kibana.username")
$env:KIBANA_PASSWORD = (buildkite-agent meta-data get "kibana.pwd")

Write-Output "~~~ Running integration tests as $env:USERNAME"
Write-Output "~~~ Integration tests: $GROUP_NAME"

go install gotest.tools/gotestsum
gotestsum --version

# Read package version from .package-version file
$PACKAGE_VERSION = Get-Content .package-version -ErrorAction SilentlyContinue
if ($PACKAGE_VERSION) {
    $PACKAGE_VERSION = "${PACKAGE_VERSION}-SNAPSHOT"
}

echo "~~~ Building test binaries"
mage build:testBinaries

# Run integration tests with gotestsum
echo "~~~ Running tests"
$env:TEST_BINARY_NAME = "elastic-agent"
$env:AGENT_VERSION = $PACKAGE_VERSION
$env:SNAPSHOT = $true

$ErrorActionPreference = 'Continue'
gotestsum --no-color -f standard-quiet --junitfile "build/${GROUP_NAME}.integration.xml" --jsonfile "build/${GROUP_NAME}.integration.out.json" -- -tags=integration -shuffle=on -timeout=2h0m0s "github.com/elastic/elastic-agent/testing/integration" -v -args "-integration.groups=$GROUP_NAME" "-integration.sudo=$TEST_SUDO"
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

exit $TESTS_EXIT_STATUS