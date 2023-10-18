$ErrorActionPreference = "Stop"

$env:GOTMPDIR = "$env:BUILDKITE_BUILD_CHECKOUT_PATH"

Write-Host "--- Build"
go env
mage build

if ($LASTEXITCODE -ne 0) {  
  exit 1 
}

Write-Host "--- Unit tests"
$env:TEST_COVERAGE = $true
mage unitTest

if ($LASTEXITCODE -ne 0) {  
  exit 1 
}
