$ErrorActionPreference = "Stop"

Write-Host "--- Build"
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
