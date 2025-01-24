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

echo "~~~ Building test binaries"
mage build:testBinaries
$osInfo = (Get-CimInstance Win32_OperatingSystem).Caption + " " + (Get-CimInstance Win32_OperatingSystem).OSArchitecture -replace " ", "_"
$root_suffix=""
if ($TEST_SUDO -eq "true") {
    $root_suffix="_sudo"
}
$fully_qualified_group_name="${GROUP_NAME}${root_suffix}_${osInfo}"
$outputXML = "build/${fully_qualified_group_name}.integration.xml"
$outputJSON = "build/${fully_qualified_group_name}.integration.out.json"
try {
    Get-Ess-Stack -StackVersion $PACKAGE_VERSION    
    Write-Output "~~~ Running integration test group: $GROUP_NAME as user: $env:USERNAME"
    gotestsum --no-color -f standard-quiet --junitfile "${outputXML}" --jsonfile "${outputJSON}" -- -tags=integration -shuffle=on -timeout=2h0m0s "github.com/elastic/elastic-agent/testing/integration" -v -args "-integration.groups=$GROUP_NAME" "-integration.sudo=$TEST_SUDO" 
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