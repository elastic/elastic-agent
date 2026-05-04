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

Write-Output "~~~ Building test binaries"
& mage build:integrationTestBinaries
if ($LASTEXITCODE -ne 0) {
    Write-Output "^^^ +++"
    Write-Output "Failed to build test binaries"
    exit 1
}

$TestsExitCode = 0
try {
    Write-Output "~~~ Running integration tests"
    # Get-Ess-Stack will start the ESS stack if it is a BK retry
    Get-Ess-Stack -StackVersion $STACK_VERSION
    # Load secrets from GCP Secret Manager via oblt-cli
    $result = ess_load_secrets
    if ($result -ne 0) {
        Write-Output "Failed to load secrets"
        exit 1
    }
    & "$PWD\.buildkite\scripts\buildkite-integration-tests.ps1" $GROUP_NAME $TEST_SUDO
    $TestsExitCode = $LASTEXITCODE
    if ($TestsExitCode -ne 0)
    {
        Write-Output "^^^ +++"
        Write-Output "Integration tests failed"
    }
} finally {
    # ess_down will destroy the ESS stack if this is a BK retry (cluster was created in this step)
    if ($Env:BUILDKITE_RETRY_COUNT -gt 0) {
        ess_down
    }
}

exit $TestsExitCode
