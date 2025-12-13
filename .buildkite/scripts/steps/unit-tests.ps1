$ErrorActionPreference = "Stop"

Write-Host "-- Fixing CRLF in git checkout --"
git config core.autocrlf input
git rm --quiet --cached -r .
git reset --quiet --hard

$env:GOTMPDIR = "$env:BUILDKITE_BUILD_CHECKOUT_PATH"
$env:GOPROXY = "https://${ARTIFACTORY_USER}:${ARTIFACTORY_API_KEY}@artifactory.elastic.dev/artifactory/api/go/go"
$env:GONOPROXY = "gopkg.in/natefinch/lumberjack.v2,gopkg.in/yaml*,github.com/rs/zerolog,gotest.tools/gotestsum"

Write-Host "--- Build"
mage build

if ($LASTEXITCODE -ne 0) {
  exit 1
}

Write-Host "--- Unit tests"
$env:TEST_COVERAGE = $true
$env:RACE_DETECTOR = $true
mage unitTest
# Copy coverage file to build directory so it can be downloaded as an artifact
Write-Host "--- Prepare artifacts"
$buildkiteJobId = $env:BUILDKITE_JOB_ID
Move-Item -Path "build/TEST-go-unit.cov" -Destination "coverage-$buildkiteJobId.out"
Move-Item -Path "build/TEST-go-unit.xml" -Destination "build/TEST-$buildkiteJobId.xml"
if ($LASTEXITCODE -ne 0) {
  exit 1
}


