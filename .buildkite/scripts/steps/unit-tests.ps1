$ErrorActionPreference = "Stop"

Write-Host "--- Build"
mage build

Write-Host "--- Unit tests"
$Env:TEST_COVERAGE = $true
mage unitTest
