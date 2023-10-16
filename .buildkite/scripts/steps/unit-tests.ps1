$ErrorActionPreference = "Stop"

Write-Host "--- Build"
mage build

Write-Host "--- Unit tests"
$env:TEST_COVERAGE = $true
mage unitTest
