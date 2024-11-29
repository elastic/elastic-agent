param (
    [string]$GROUP_NAME,
    [string]$TEST_SUDO
)

echo "~~~ Preparing environment"

$PSVersionTable.PSVersion

. "$PWD\.buildkite\scripts\steps\ess.ps1"

go install gotest.tools/gotestsum
gotestsum --version

# Read package version from .package-version file
$PACKAGE_VERSION = Get-Content .package-version -ErrorAction SilentlyContinue
if ($PACKAGE_VERSION) {
    $PACKAGE_VERSION = "${PACKAGE_VERSION}-SNAPSHOT"
}
$env:TEST_BINARY_NAME = "elastic-agent"
$env:AGENT_VERSION = $PACKAGE_VERSION
$env:SNAPSHOT = $true

Write-Host "--- Prepare BK test analytics token :vault:"
$BUILDKITE_ANALYTICS_TOKEN = & vault kv get -field=token kv/ci-shared/platform-ingest/buildkite_analytics_token
[System.Environment]::SetEnvironmentVariable("BUILDKITE_ANALYTICS_TOKEN", $BUILDKITE_ANALYTICS_TOKEN, [System.EnvironmentVariableTarget]::Process)

echo "~~~ Building test binaries"
mage build:testBinaries

try {
    Get-Ess-Stack -StackVersion $PACKAGE_VERSION    
    Write-Output "~~~ Running integration test group: $GROUP_NAME as user: $env:USERNAME"
    gotestsum --no-color -f standard-quiet --junitfile "build/${GROUP_NAME}.integration.xml" --jsonfile "build/${GROUP_NAME}.integration.out.json" -- -tags=integration -shuffle=on -timeout=2h0m0s "github.com/elastic/elastic-agent/testing/integration" -v -args "-integration.groups=$GROUP_NAME" "-integration.sudo=$TEST_SUDO"    
} finally {
    ess_down
    # Generate HTML report if XML output exists
    $outputXML = "build/${GROUP_NAME}.integration.xml"
    if (Test-Path $outputXML) {
        # Install junit2html if not installed
        go install github.com/alexec/junit2html@latest
        Get-Content $outputXML | junit2html > "build/TEST-report.html"
    } else {
        Write-Output "Cannot generate HTML test report: $outputXML not found"
    }
}
