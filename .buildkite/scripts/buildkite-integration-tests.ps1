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

# Start Process Monitor when PROCMON_CAPTURE=true so the .pml trace is collected
# as a build artifact alongside the other diagnostics.
$procmonExe = $null
$procmonPml = $null
if ($env:PROCMON_CAPTURE -eq "true")
{
    $procmonDir = Join-Path $env:TEMP "procmon"
    $procmonExe = Join-Path $procmonDir "Procmon64.exe"

    if (-not (Test-Path $procmonExe))
    {
        Write-Output "~~~ Downloading Process Monitor"
        $procmonZip = Join-Path $env:TEMP "ProcessMonitor.zip"
        try
        {
            Invoke-WebRequest -Uri "https://download.sysinternals.com/files/ProcessMonitor.zip" -OutFile $procmonZip -UseBasicParsing
            Expand-Archive -Path $procmonZip -DestinationPath $procmonDir -Force
        }
        catch
        {
            Write-Output "WARNING: failed to download Process Monitor (continuing without it): $_"
            $procmonExe = $null
        }
    }

    if ($procmonExe -and (Test-Path $procmonExe))
    {
        $null = New-Item -ItemType Directory -Force -Path "build/diagnostics"
        $procmonPml = "build/diagnostics/procmon-${GROUP_NAME}${root_suffix}.pml"
        Write-Output "~~~ Starting Process Monitor; backing file: $procmonPml"
        Start-Process -FilePath $procmonExe -ArgumentList "/AcceptEula", "/Quiet", "/BackingFile", $procmonPml -WindowStyle Hidden
    }
}

try
{
    Write-Output "~~~ Integration tests: $GROUP_NAME as user: $env:USERNAME"
    # -test.timeout=2h0m0s is set because some tests normally take up to 45 minutes.
    # This 2-hour timeout provides enough room for future, potentially longer tests,
    # while still enforcing a reasonable upper limit on total execution time.
    # See: https://pkg.go.dev/cmd/go#hdr-Testing_flags
    $gotestFlags = @("-test.shuffle=on", "-test.timeout=2h0m0s")
    if($env:BUILDKITE_PULL_REQUEST -ne "false")
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
    if ($procmonExe -and (Test-Path $procmonExe))
    {
        Write-Output "~~~ Stopping Process Monitor"
        # /Terminate signals the running instance to flush and finalise the .pml file.
        & $procmonExe /Terminate
        # Wait for procmon to exit so the file is fully written before the artifact
        # upload step reads it.
        $procmonProcess = Get-Process -Name Procmon64 -ErrorAction SilentlyContinue
        if ($procmonProcess)
        {
            $procmonProcess | Wait-Process -Timeout 30 -ErrorAction SilentlyContinue
        }
        Write-Output "~~~ Process Monitor trace saved to $procmonPml"
    }

    if (Test-Path $outputXML)
    {
        # Install junit2html if not installed
        go install github.com/kitproj/junit2html@latest
        Get-Content $outputXML | junit2html > "build/TEST-report.html"
    }
    else
    {
        Write-Output "Cannot generate HTML test report: $outputXML not found"
    }
}

exit $TestsExitCode
