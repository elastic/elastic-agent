$ErrorActionPreference = "Stop"

Write-Host "--- Unit tests"
$Env:TEST_COVERAGE = $true
mage unitTest
