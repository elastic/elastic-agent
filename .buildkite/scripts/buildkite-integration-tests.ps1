param(
    [string]$GROUP_NAME,
    [string]$TEST_SUDO
)

if (-not $GROUP_NAME)
{
    Write-Error "Error: Specify the group name: buildkite-integration-tests.ps1 <group_name> <true|false>"
    exit 1
}

if (-not $TEST_SUDO)
{
    Write-Error "Error: Specify the test sudo: buildkite-integration-tests.ps1 <group_name> <true|false>"
    exit 1
}

if (-not $env:TEST_PACKAGE)
{
    $env:TEST_PACKAGE = "github.com/elastic/elastic-agent/testing/integration"
}

# TODO: make is not available on Windows yet hence we cannot use make install-gotestsum
go install gotest.tools/gotestsum
gotestsum --version

$env:TEST_BINARY_NAME = "elastic-agent"

if (-not $env:AGENT_VERSION)
{
    if (Test-Path .package-version)
    {
        $packageContent = Get-Content .package-version -Raw | ConvertFrom-Json
        $env:AGENT_VERSION = $packageContent.version
        Write-Output "~~~ Agent version: $env:AGENT_VERSION (from .package-version)"
    }
    else
    {
        # Parsing version.go. Will be simplified here: https://github.com/elastic/ingest-dev/issues/4925
        $AGENT_VERSION = (Get-Content version/version.go | Select-String -Pattern 'const defaultBeatVersion =' | ForEach-Object { $_ -replace '.*?"(.*?)".*', '$1' })
        $env:AGENT_VERSION = $AGENT_VERSION + "-SNAPSHOT"
        Write-Output "~~~ Agent version: $env:AGENT_VERSION (from version/version.go)"
    }
}
else
{
    Write-Output "~~~ Agent version: $env:AGENT_VERSION (specified by env var)"
}

$env:SNAPSHOT = $true

Write-Host "~~~ Running integration tests as $env:USERNAME"

$osInfo = (Get-CimInstance Win32_OperatingSystem).Caption + " " + (Get-CimInstance Win32_OperatingSystem).OSArchitecture -replace " ", "_"
$root_suffix = ""
if ($TEST_SUDO -eq "true")
{
    $root_suffix = "_sudo"
}
$fully_qualified_group_name = "${GROUP_NAME}${root_suffix}_${osInfo}"
$outputXML = "build/${fully_qualified_group_name}.integration.xml"
$outputJSON = "build/${fully_qualified_group_name}.integration.out.json"

$TestsExitCode = 0

try
{
    Write-Output "~~~ Integration tests: $GROUP_NAME as user: $env:USERNAME"
    # -test.timeout=2h0m0s is set because some tests normally take up to 45 minutes.
    # This 2-hour timeout provides enough room for future, potentially longer tests,
    # while still enforcing a reasonable upper limit on total execution time.
    # See: https://pkg.go.dev/cmd/go#hdr-Testing_flags
    $gotestFlags = @("-test.shuffle=on", "-test.timeout=2h0m0s")
    if(-not ([string]::IsNullOrEmpty($env:BUILDKITE_PULL_REQUEST)))
    {
        $gotestFlags += "-test.short"
    }
    $gotestArgs = @("-tags=integration", ${gotestFlags}, "$env:TEST_PACKAGE", "-v", "-args", "-integration.groups=$GROUP_NAME", "-integration.sudo=$TEST_SUDO")
    & gotestsum --no-color -f standard-quiet --junitfile-hide-skipped-tests --junitfile "${outputXML}" --jsonfile "${outputJSON}" -- @gotestArgs
    $TestsExitCode = $LASTEXITCODE

    if ($TestsExitCode -ne 0)
    {
        Write-Output "^^^ +++"
        Write-Output "Integration tests failed"
    }
}
finally
{
    if (Test-Path $outputXML)
    {
        # Install junit2html if not installed
        go install github.com/alexec/junit2html@latest
        Get-Content $outputXML | junit2html > "build/TEST-report.html"
    }
    else
    {
        Write-Output "Cannot generate HTML test report: $outputXML not found"
    }
}

exit $TestsExitCode