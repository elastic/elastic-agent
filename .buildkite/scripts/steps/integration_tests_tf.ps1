param (
    [string]$GROUP_NAME,
    [string]$TEST_SUDO
)

Write-Output "~~~ Preparing environment"

$PSVersionTable.PSVersion

. "$PWD\.buildkite\scripts\steps\ess.ps1"

# Read package version from .package-version file
$PACKAGE_VERSION = Get-Content .package-version -ErrorAction SilentlyContinue
if ($PACKAGE_VERSION) {
    $PACKAGE_VERSION = "${PACKAGE_VERSION}-SNAPSHOT"
}

Write-Output "~~~ Building test binaries"
& mage build:testBinaries
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to build test binaries"
    exit 1
}

$TestsExitCode = 0
try {
    # Get-Ess-Stack will start the ESS stack if it is a BK retry, otherwise it will retrieve ESS stack metadata
    Get-Ess-Stack -StackVersion $PACKAGE_VERSION
    & "$PWD\.buildkite\scripts\buildkite-integration-tests.ps1" $GROUP_NAME $TEST_SUDO
    $TestsExitCode = $LASTEXITCODE
} finally {
    # ess_down will destroy the ESS stack if tf state file is found, aka if this is a BK retry
    ess_down
}

exit $TestsExitCode
