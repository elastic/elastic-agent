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
    Write-Output "^^^ +++"
    Write-Output "Failed to build test binaries"
    exit 1
}

$TestsExitCode = 0
try {
    Write-Output "~~~ Running integration tests"
    # Get-Ess-Stack will start the ESS stack if it is a BK retry, otherwise it will retrieve ESS stack metadata
    Get-Ess-Stack -StackVersion $PACKAGE_VERSION

    # Load the ESS stack secrets
    # Get the cluster name from the meta-data (CI specific)
    # QUESTION: should we support the case when using the ESS stack in local environment?
    $ClusterName = & buildkite-agent meta-data get cluster-name
    & oblt-cli cluster secrets env --cluster-nam $ClusterName --output-file="env.sh"

    # TODO: source the secrets file
    source "${PWD}/env.sh" || rm "${PWD}/env.sh"

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
