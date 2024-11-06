$ErrorActionPreference = "Stop"

Write-Host "~~~ Receiving ESS stack metadata"
$env:ELASTICSEARCH_HOST = (buildkite-agent meta-data get "es.host")
$env:ELASTICSEARCH_USERNAME = (buildkite-agent meta-data get "es.username")
$env:ELASTICSEARCH_PASSWORD = (buildkite-agent meta-data get "es.pwd")
$env:KIBANA_HOST = (buildkite-agent meta-data get "kibana.host")
$env:KIBANA_USERNAME = (buildkite-agent meta-data get "kibana.username")
$env:KIBANA_PASSWORD = (buildkite-agent meta-data get "kibana.pwd")

Write-Host "~~~ Building test binaries"
mage build:testBinaries


Write-Host "~~~ Running integration tests"
Start-Process -FilePath "powershell" -ArgumentList "-File to-do.ps1 $args" -Verb RunAs
