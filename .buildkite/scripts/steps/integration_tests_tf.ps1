param (
    [string]$GROUP_NAME,
    [string]$TEST_SUDO
)

Write-Output "~~~ Preparing environment"

$PSVersionTable.PSVersion

. "$PWD\.buildkite\scripts\steps\ess.ps1"

# Override the stack version from `.package-version` contents
# There is a time when the current snapshot is not available on cloud yet, so we cannot use the latest version automatically
# This file is managed by an automation (mage integration:UpdateAgentPackageVersion) that check if the snapshot is ready
$packageVersionContent = Get-Content .package-version -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
if ($packageVersionContent -and $packageVersionContent.stack_version ) {
    $STACK_VERSION = $packageVersionContent.stack_version
}
if ($packageVersionContent -and $packageVersionContent.stack_build_id ) {
    $STACK_BUILD_ID = $packageVersionContent.stack_build_id
}

Write-Output "~~~ Building test binaries"
& mage build:testBinaries
if ($LASTEXITCODE -ne 0) {
    Write-Output "^^^ +++"
    Write-Output "Failed to build test binaries"
    exit 1
}

$TestsExitCode = 0
try {
    Write-Output "~~~ Running integration tests"
    # Get-Ess-Stack will start the ESS stack if it is a BK retry, otherwise it will retrieve ESS stack metadata
    Get-Ess-Stack -StackVersion $STACK_VERSION -StackBuildId $STACK_BUILD_ID
    & "$PWD\.buildkite\scripts\buildkite-integration-tests.ps1" $GROUP_NAME $TEST_SUDO
    $TestsExitCode = $LASTEXITCODE
    if ($TestsExitCode -ne 0)
    {
        Write-Output "^^^ +++"
        Write-Output "Integration tests failed"
    }
} finally {
    # ess_down will destroy the ESS stack if tf state file is found, aka if this is a BK retry
    ess_down
}

exit $TestsExitCode
