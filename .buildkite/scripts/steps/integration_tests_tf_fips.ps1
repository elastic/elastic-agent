param (
    [string]$GROUP_NAME,
    [string]$TEST_SUDO
)

. "$PWD\.buildkite\scripts\steps\ess.ps1"

if (-not $GROUP_NAME) {
    Write-Error "Error: Specify the group name: integration_tests_tf_fips.ps1 <group_name> <true|false>"
    exit 1
}

if (-not $TEST_SUDO) {
    Write-Error "Error: Specify the test sudo: integration_tests_tf_fips.ps1 <group_name> <true|false>"
    exit 1
}

$fipsKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"

Write-Output "~~~ Enabling Windows FIPS algorithm policy"
New-Item -Path $fipsKeyPath -Force | Out-Null
Set-ItemProperty -Path $fipsKeyPath -Name "Enabled" -Value 1 -Type DWord

Write-Output "~~~ Reloading group policy"
& gpupdate /force
if ($LASTEXITCODE -ne 0) {
    Write-Error "gpupdate /force failed (exit=$LASTEXITCODE)"
    exit 1
}

Write-Output "~~~ Verifying FIPS algorithm policy is enabled"
$enabled = (Get-ItemProperty -Path $fipsKeyPath -Name "Enabled" -ErrorAction Stop).Enabled
Write-Output "FipsAlgorithmPolicy.Enabled = $enabled"
if ($enabled -ne 1) {
    Write-Error "FIPS algorithm policy is not enabled (Enabled=$enabled); aborting before tests run"
    exit 1
}

# Stack version, same as integration_tests_tf.ps1. FRS only offers plain
# versions, so the build id is not used for FIPS.
$packageVersionContent = Get-Content .package-version -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
if ($packageVersionContent -and $packageVersionContent.stack_version) {
    $STACK_VERSION = $packageVersionContent.stack_version
    $STACK_BUILD_ID = $packageVersionContent.stack_build_id
}

Write-Output "~~~ Building integration test binaries"
& mage build:integrationTestBinaries
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to build test binaries"
    exit 1
}

$TestsExitCode = 0
try {
    Write-Output "~~~ Running integration tests"
    # Get-Ess-Stack only starts a new stack if this is a manual BK retry.
    # Otherwise the shared FRS stack from the start step is used.
    Get-Ess-Stack -StackVersion $STACK_VERSION -StackBuildId $STACK_BUILD_ID

    $result = ess_load_secrets
    if ($result -ne 0) {
        Write-Error "Failed to load secrets"
        exit 1
    }
    & "$PWD\.buildkite\scripts\buildkite-integration-tests.ps1" $GROUP_NAME $TEST_SUDO
    $TestsExitCode = $LASTEXITCODE
} finally {
    # ess_down only destroys the stack if this step created it (manual retry).
    if ($Env:BUILDKITE_RETRY_COUNT -gt 0 -and $Env:BUILDKITE_RETRY_TYPE -ne "automatic") {
        ess_down
    }
}

exit $TestsExitCode
