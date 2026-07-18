# Runs the unit tests as a freshly created local user that has never logged
# on interactively and therefore has no user profile directory. This catches
# code that assumes a profile directory exists, e.g. os/user.Current() failing
# while creating the gRPC control socket.
# See https://github.com/elastic/elastic-agent/issues/15626
$ErrorActionPreference = "Stop"

Write-Host "-- Fixing CRLF in git checkout --"
git config core.autocrlf input
git rm --quiet --cached -r .
git reset --quiet --hard

$checkout = $env:BUILDKITE_BUILD_CHECKOUT_PATH

Write-Host "--- Creating a test user without a profile directory"
$suffix = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
$username = "eanp$suffix"
$password = "aB1!" + [System.Guid]::NewGuid().ToString("N").Substring(0, 16)

# /y suppresses the interactive confirmation net.exe asks for when the
# password is longer than 14 characters.
net user $username $password /add /y
if ($LASTEXITCODE -ne 0) { throw "failed to create user $username" }
# Make the user an administrator so that the only difference from the regular
# unit test run is the missing profile directory.
net localgroup Administrators $username /add
if ($LASTEXITCODE -ne 0) { throw "failed to add $username to Administrators" }

if (Test-Path (Join-Path "C:\Users" $username)) {
  throw "user $username already has a profile directory, the run would be invalid"
}

# Start-Process -Credential requires the Secondary Logon service.
Set-Service seclogon -StartupType Manual -ErrorAction SilentlyContinue
Start-Service seclogon

Write-Host "--- Granting the test user access to the checkout and Go toolchain"
# Inheritable ACEs propagate to the whole subtree, /T is not needed because
# nothing below these directories disables ACL inheritance.
icacls $checkout /grant "${username}:(OI)(CI)F" /Q
if ($LASTEXITCODE -ne 0) { throw "failed to grant access to $checkout" }
$goRoot = (& go env GOROOT).Trim()
icacls $goRoot /grant "${username}:(OI)(CI)RX" /Q
foreach ($tool in @("go", "mage", "git")) {
  $cmd = Get-Command $tool -ErrorAction SilentlyContinue
  if ($cmd) {
    icacls (Split-Path $cmd.Source) /grant "${username}:(OI)(CI)RX" /Q
  }
}

# Scratch area for the test user's home, temp files and Go caches, since it
# has no profile directory to put them in.
$scratch = "C:\no-profile-scratch"
New-Item -ItemType Directory -Force -Path $scratch, (Join-Path $scratch "tmp") | Out-Null
icacls $scratch /grant "${username}:(OI)(CI)F" /Q
if ($LASTEXITCODE -ne 0) { throw "failed to grant access to $scratch" }

# The race detector is not supported on windows/arm64, see unit-tests.ps1.
$raceDetector = "false"
if ($env:PROCESSOR_ARCHITECTURE -ne "ARM64" -and $env:DISABLE_RACE_DETECTOR -ne "true") {
  $raceDetector = "true"
}

# A process started with Start-Process -Credential does not inherit this
# shell's environment, so everything the test run needs is written into the
# runner script executed by the test user. The runner is a cmd batch script
# rather than PowerShell because Windows PowerShell with redirected stderr
# wraps native stderr output (e.g. "go: downloading ...") in error records,
# which terminate the script under ErrorActionPreference=Stop.
# HOME and USERPROFILE point at the scratch directory so the Go toolchain has
# a writable home; this does not affect os/user.Current(), which resolves the
# profile from the process token and still fails for this user.
$runner = Join-Path $scratch "runner.cmd"
$stdoutLog = Join-Path $scratch "stdout.log"
$stderrLog = Join-Path $scratch "stderr.log"

@"
@echo off
cd /d "$checkout" || exit /b 1
set "PATH=$scratch\gopath\bin;$env:PATH"
set "HOME=$scratch"
set "USERPROFILE=$scratch"
set "TEMP=$scratch\tmp"
set "TMP=$scratch\tmp"
set "GOTMPDIR=$scratch\tmp"
set "GOPATH=$scratch\gopath"
set "GOCACHE=$scratch\gocache"
set "GOMODCACHE=$scratch\gomodcache"
set "MAGEFILE_CACHE=$scratch\magecache"
set "TEST_COVERAGE=true"
set "RACE_DETECTOR=$raceDetector"
rem The checkout is owned by the CI user, not the test user running this script.
git config --global --add safe.directory "*" 2>&1
rem Merge stderr into stdout so the streamed log stays in order.
mage unitTest 2>&1
exit /b %ERRORLEVEL%
"@ | Set-Content -Path $runner -Encoding ASCII

Write-Host "--- Unit tests (as $username, no user profile)"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential(".\$username", $securePassword)

$process = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" `
  -ArgumentList @("/d", "/c", $runner) `
  -Credential $credential -WorkingDirectory $checkout `
  -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog `
  -PassThru

# Stream the test output while the child process runs.
$offset = 0
do {
  $exited = $process.WaitForExit(5000)
  try {
    if (Test-Path $stdoutLog) {
      $content = Get-Content $stdoutLog -Raw -ErrorAction Stop
      if ($content -and $content.Length -gt $offset) {
        Write-Host $content.Substring($offset) -NoNewline
        $offset = $content.Length
      }
    }
  } catch {
    # The log file can be transiently locked by the child process.
  }
} until ($exited)

if (Test-Path $stderrLog) {
  $stderrContent = Get-Content $stderrLog -Raw
  if ($stderrContent) {
    Write-Host "--- stderr"
    Write-Host $stderrContent
  }
}

$process.WaitForExit()
$testsExitCode = $process.ExitCode
if ($null -eq $testsExitCode) { $testsExitCode = 1 }
Write-Host "--- Unit tests exited with code $testsExitCode"

net user $username /delete | Out-Null

# Copy coverage file to build directory so it can be downloaded as an artifact
Write-Host "--- Prepare artifacts"
$buildkiteJobId = $env:BUILDKITE_JOB_ID
if (Test-Path "build/TEST-go-unit.cov") {
  Move-Item -Path "build/TEST-go-unit.cov" -Destination "coverage-$buildkiteJobId.out"
}
if (Test-Path "build/TEST-go-unit.xml") {
  Move-Item -Path "build/TEST-go-unit.xml" -Destination "build/TEST-$buildkiteJobId.xml"
}

exit $testsExitCode
