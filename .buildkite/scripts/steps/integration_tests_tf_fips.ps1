param (
    [string]$GROUP_NAME,
    [string]$TEST_SUDO
)

$ErrorActionPreference = "Stop"

if (-not $GROUP_NAME) {
    Write-Error "Error: Specify the group name: integration_tests_tf_fips.ps1 <group_name> <true|false>"
    exit 1
}

if (-not $TEST_SUDO) {
    Write-Error "Error: Specify the test sudo: integration_tests_tf_fips.ps1 <group_name> <true|false>"
    exit 1
}

$fipsKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"

Write-Output "~~~ Enabling Windows FIPS algorithm policy"
New-Item -Path $fipsKeyPath -Force | Out-Null
Set-ItemProperty -Path $fipsKeyPath -Name "Enabled" -Value 1 -Type DWord

Write-Output "~~~ Reloading group policy"
& gpupdate /force
if ($LASTEXITCODE -ne 0) {
    Write-Error "gpupdate /force failed (exit=$LASTEXITCODE)"
    exit 1
}

Write-Output "~~~ Verifying FIPS algorithm policy is enabled"
$enabled = (Get-ItemProperty -Path $fipsKeyPath -Name "Enabled" -ErrorAction Stop).Enabled
Write-Output "FipsAlgorithmPolicy.Enabled = $enabled"
if ($enabled -ne 1) {
    Write-Error "FIPS algorithm policy is not enabled (Enabled=$enabled); aborting before tests run"
    exit 1
}

Write-Output "~~~ Receiving ESS stack metadata"
$metadataPrefix = "fips."
$envMap = @{
    "ELASTICSEARCH_HOST"      = "${metadataPrefix}es.host"
    "ELASTICSEARCH_USERNAME"  = "${metadataPrefix}es.username"
    "ELASTICSEARCH_PASSWORD"  = "${metadataPrefix}es.pwd"
    "KIBANA_HOST"             = "${metadataPrefix}kibana.host"
    "KIBANA_USERNAME"         = "${metadataPrefix}kibana.username"
    "KIBANA_PASSWORD"         = "${metadataPrefix}kibana.pwd"
    "ELASTIC_APM_SERVER_URL"  = "${metadataPrefix}integrations_server.host"
}
foreach ($name in $envMap.Keys) {
    $value = & buildkite-agent meta-data get $envMap[$name]
    if ($LASTEXITCODE -ne 0 -or -not $value) {
        Write-Error "Failed to read meta-data key $($envMap[$name])"
        exit 1
    }
    [System.Environment]::SetEnvironmentVariable($name, $value)
}
Write-Output "Elasticsearch Host: $env:ELASTICSEARCH_HOST"

Write-Output "~~~ Building integration test binaries"
& mage build:integrationTestBinaries
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to build test binaries"
    exit 1
}

& "$PWD\.buildkite\scripts\buildkite-integration-tests.ps1" $GROUP_NAME $TEST_SUDO
exit $LASTEXITCODE
