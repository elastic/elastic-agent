echo "~~~ Preparing environment"

$PSVersionTable.PSVersion

# TODO: make is not available on Windows yet
#       hence we cannot use make install-gotestsum
go install gotest.tools/gotestsum
gotestsum --version

# Read package version from .package-version file
$PACKAGE_VERSION = Get-Content .package-version -ErrorAction SilentlyContinue
if ($PACKAGE_VERSION) {
    $PACKAGE_VERSION = "${PACKAGE_VERSION}-SNAPSHOT"
}
$env:TEST_BINARY_NAME = "elastic-agent"
# Parsing version.go. Will be simplified here: https://github.com/elastic/ingest-dev/issues/4925
$AGENT_VERSION = (Get-Content version/version.go | Select-String -Pattern 'const defaultBeatVersion =' | ForEach-Object { $_ -replace '.*?"(.*?)".*', '$1' })
$env:AGENT_VERSION = $AGENT_VERSION + "-SNAPSHOT"

echo "~~~ Agent version: $env:AGENT_VERSION"
$env:SNAPSHOT = $true

echo "~~~ Building test binaries"
& mage build:testBinaries
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to build test binaries"
    exit 1
}
$osInfo = (Get-CimInstance Win32_OperatingSystem).Caption + " " + (Get-CimInstance Win32_OperatingSystem).OSArchitecture -replace " ", "_"
$fully_qualified_group_name="fleet_sudo_${osInfo}"
$outputXML = "build/${fully_qualified_group_name}.integration.xml"
$outputJSON = "build/${fully_qualified_group_name}.integration.out.json"
$TestsExitCode = 0
try {
    Write-Output "~~~ Running serverless integration tests"
    $gotestArgs = @("-tags=integration", "-shuffle=on", "-timeout=2h0m0s", "-run=TestLogIngestionFleetManaged")
    $gotestArgs += @("github.com/elastic/elastic-agent/testing/integration", "-v", "-args", "-integration.groups=fleet", "-integration.sudo=true")
    & gotestsum --no-color -f standard-quiet --junitfile-hide-skipped-tests --junitfile "${outputXML}" --jsonfile "${outputJSON}" -- @gotestArgs
    $TestsExitCode = $LASTEXITCODE
} finally {
    if (Test-Path $outputXML) {
        # Install junit2html if not installed
        go install github.com/alexec/junit2html@latest
        Get-Content $outputXML | junit2html > "build/TEST-report.html"
    } else {
        Write-Output "Cannot generate HTML test report: $outputXML not found"
    }
}

if ($TestsExitCode -ne 0) {
    exit 1
}
