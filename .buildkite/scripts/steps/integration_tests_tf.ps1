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
    $STACK_BUILD_ID = $packageVersionContent.stack_build_id
}

Write-Output "~~~ Building test binaries"
& mage build:integrationTestBinaries
if ($LASTEXITCODE -ne 0) {
    Write-Output "^^^ +++"
    Write-Output "Failed to build test binaries"
    exit 1
}

# When AGENT_ARTIFACT_STEP is set the step does not depend on the packaging
# step in the pipeline; instead the setup above runs while packaging is still
# in progress and we only wait for the artifacts right before the tests.
if ($env:AGENT_ARTIFACT_STEP) {
    & "$PWD\.buildkite\scripts\steps\wait-for-step.ps1" -StepKey $env:AGENT_ARTIFACT_STEP
    if ($LASTEXITCODE -ne 0) {
        Write-Output "^^^ +++"
        Write-Output "Step $env:AGENT_ARTIFACT_STEP did not succeed"
        exit 1
    }
    if (-not $env:AGENT_ARTIFACT_GLOBS) {
        Write-Error "AGENT_ARTIFACT_GLOBS must be set together with AGENT_ARTIFACT_STEP"
        exit 1
    }
    Write-Output "~~~ Downloading agent packages from step $env:AGENT_ARTIFACT_STEP"
    foreach ($glob in ($env:AGENT_ARTIFACT_GLOBS -split ' ')) {
        & buildkite-agent artifact download $glob . --step $env:AGENT_ARTIFACT_STEP
        if ($LASTEXITCODE -ne 0) {
            Write-Output "^^^ +++"
            Write-Output "Failed to download $glob from step $env:AGENT_ARTIFACT_STEP"
            exit 1
        }
    }
}

$TestsExitCode = 0
try {
    Write-Output "~~~ Running integration tests"
    # Get-Ess-Stack will start the ESS stack if it is a BK retry
    Get-Ess-Stack -StackVersion $STACK_VERSION -StackBuildId $STACK_BUILD_ID

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
    if ($Env:BUILDKITE_RETRY_COUNT -gt 0 -and $Env:BUILDKITE_RETRY_TYPE -ne "automatic") {
        ess_down
    }
}

exit $TestsExitCode
