$ErrorActionPreference = "Stop"
Write-Host "--- Unit tests"
#debug
Write-Host "GOPATH: $env:GOPATH"
# Get-ChildItem -Path $env:GOPATH\bin

# run tests
$Env:TEST_COVERAGE = $true
.\gopath\mage unitTest

