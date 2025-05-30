param (
    [string]$GROUP_NAME,
    [string]$TEST_SUDO,
    [string]$TEST_NAME_PATTERN = ""
)

echo "~~~ Preparing environment"

$PSVersionTable.PSVersion

. "$PWD\.buildkite\scripts\steps\ess.ps1"

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
$root_suffix=""
if ($TEST_SUDO -eq "true") {
    $root_suffix="_sudo"
}
$fully_qualified_group_name="${GROUP_NAME}${root_suffix}_${osInfo}"
$outputXML = "build/${fully_qualified_group_name}.integration.xml"
$outputJSON = "build/${fully_qualified_group_name}.integration.out.json"
$TestsExitCode = 0
try {
    Get-Ess-Stack -StackVersion $PACKAGE_VERSION
    Write-Output "~~~ Running integration test group: $GROUP_NAME as user: $env:USERNAME"
    $gotestArgs = @("-tags=integration", "-shuffle=on", "-timeout=2h0m0s")
    if ($TEST_NAME_PATTERN -ne "") {
        $gotestArgs += "-run=${TEST_NAME_PATTERN}"
    }
    $gotestArgs += @("github.com/elastic/elastic-agent/testing/integration", "-v", "-args", "-integration.groups=$GROUP_NAME", "-integration.sudo=$TEST_SUDO")
    & gotestsum --no-color -f standard-quiet --junitfile-hide-skipped-tests --junitfile "${outputXML}" --jsonfile "${outputJSON}" -- @gotestArgs
    $TestsExitCode = $LASTEXITCODE
} finally {
    ess_down

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
