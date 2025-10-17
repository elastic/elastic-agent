# PowerShell script for packaging Windows Docker containers in Buildkite
# This script runs on a Windows agent with Docker Desktop in Windows container mode

$ErrorActionPreference = "Stop"

Write-Host "--- Setting up environment"

# Check if MANIFEST_URL is set
if (-not $env:MANIFEST_URL) {
    $env:MANIFEST_URL = & buildkite-agent meta-data get MANIFEST_URL --default ""
    if (-not $env:MANIFEST_URL) {
        Write-Host "ERROR: Missing MANIFEST_URL variable or empty string provided" -ForegroundColor Red
        exit 1
    }
}

# Set MAGEFILE_VERBOSE if not set
if (-not $env:MAGEFILE_VERBOSE) {
    $env:MAGEFILE_VERBOSE = & buildkite-agent meta-data get MAGEFILE_VERBOSE --default "0"
}

# Create the agent drop path
$env:AGENT_DROP_PATH = "build/elastic-agent-drop"
New-Item -ItemType Directory -Force -Path $env:AGENT_DROP_PATH | Out-Null

Write-Host "+++ Downloading Windows binary artifact from previous step"
# Download the pre-built Windows binary from the Linux cross-build step
& buildkite-agent artifact download "build/golang-crossbuild/elastic-agent-windows-amd64.exe" .
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to download Windows binary artifact" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "+++ Verifying Docker is in Windows container mode"
$dockerInfo = & docker info 2>&1
if ($dockerInfo -match "OSType: linux") {
    Write-Host "ERROR: Docker is in Linux container mode. Please switch to Windows containers." -ForegroundColor Red
    Write-Host "Run: & 'C:\Program Files\Docker\Docker\DockerCli.exe' -SwitchWindowsEngine" -ForegroundColor Yellow
    exit 1
}
Write-Host "SUCCESS: Docker is in Windows container mode" -ForegroundColor Green

Write-Host "+++ Running mage package for Windows Docker"
# Set environment for Windows Docker packaging
$env:PLATFORMS = "windows/amd64"
$env:PACKAGES = "docker"

# Run mage targets
$mageTargets = @("clean", "downloadManifest", "packageUsingDRA")
& mage $mageTargets

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Mage packaging failed" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "+++ Listing built artifacts"
Get-ChildItem -Recurse build/distributions/ | Format-Table -AutoSize

Write-Host "SUCCESS: Windows Docker packaging completed successfully" -ForegroundColor Green
