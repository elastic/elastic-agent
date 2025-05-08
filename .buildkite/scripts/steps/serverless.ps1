function serverless_up {
  Write-Output "~~~ Starting Serverless Observability project"

  $Workspace = & git rev-parse --show-toplevel
  $TfDir = Join-Path -Path $Workspace -ChildPath "test_infra/serverless/"

  $Env:EC_API_KEY = Retry-Command -ScriptBlock {
    vault kv get -field=apiKey kv/ci-shared/platform-ingest/platform-ingest-ec-prod
  }

  if (-not $Env:EC_API_KEY) {
      Write-Error "Error: Failed to get EC API key from vault"
      exit 1
  }

  Push-Location -Path $TfDir
  & terraform init
  & terraform apply -auto-approve

  $Env:ELASTICSEARCH_HOST = & terraform output -raw es_host
  $Env:ELASTICSEARCH_USERNAME = & terraform output -raw es_username
  $Env:ELASTICSEARCH_PASSWORD = & terraform output -raw es_password
  $Env:KIBANA_HOST = & terraform output -raw kibana_endpoint
  $Env:KIBANA_USERNAME = $Env:ELASTICSEARCH_USERNAME
  $Env:KIBANA_PASSWORD = $Env:ELASTICSEARCH_PASSWORD
  Pop-Location
}

function serverless_down {
  $Workspace = & git rev-parse --show-toplevel
  $TfDir = Join-Path -Path $Workspace -ChildPath "test_infra/serverless/"
  $stateFilePath = Join-Path -Path $TfDir -ChildPath "terraform.tfstate"

  if (-not (Test-Path -Path $stateFilePath)) {
    Write-Output "Terraform state file not found. Skipping Serverless Observability project destroy."
    return 0
  }
  Write-Output "~~~ Tearing down the Serverless Observability project Stack(created for this step)"
  try {
    $Env:EC_API_KEY = Retry-Command -ScriptBlock {
      vault kv get -field=apiKey kv/ci-shared/platform-ingest/platform-ingest-ec-prod
    }
    Push-Location -Path $TfDir
    & terraform init
    & terraform destroy -auto-approve
    Pop-Location
  } catch {
    Write-Output "Error: Failed to destroy Serverless Observability project(it will be auto-deleted later): $_"
  }
}

function Retry-Command {
  param (
      [scriptblock]$ScriptBlock,
      [int]$MaxRetries = 3,
      [int]$DelaySeconds = 5
  )

  $lastError = $null

  for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
      try {
        $result = & $ScriptBlock
        return $result
      }
      catch {
          $lastError = $_
          Write-Warning "Attempt $attempt failed: $($_.Exception.Message)"
          Write-Warning "Retrying in $DelaySeconds seconds..."
          Start-Sleep -Seconds $DelaySeconds
      }
  }

  Write-Error "All $MaxRetries attempts failed. Original error: $($lastError.Exception.Message)"
  throw $lastError.Exception
}

function Get-Serverless-Project {
  if ($Env:BUILDKITE_RETRY_COUNT -gt 0) {
      Write-Output "The step is retried, starting the Serverless project again"
      serverless_up
      Write-Output "Serverless project is up. ES_HOST: $Env:ELASTICSEARCH_HOST"
  } else {
      # For the first run, we retrieve ESS stack metadata
      Write-Output "~~~ Receiving Serverless project metadata"
      $Env:ELASTICSEARCH_HOST = & buildkite-agent meta-data get "serverless.es.host"
      $Env:ELASTICSEARCH_USERNAME = & buildkite-agent meta-data get "serverless.es.username"
      $Env:ELASTICSEARCH_PASSWORD = & buildkite-agent meta-data get "serverless.es.pwd"
      $Env:KIBANA_HOST = & buildkite-agent meta-data get "serverless.kibana.host"
      $Env:KIBANA_USERNAME = & buildkite-agent meta-data get "serverless.kibana.username"
      $Env:KIBANA_PASSWORD = & buildkite-agent meta-data get "serverless.kibana.pwd"
      Write-Output "Received Serverless project data from previous step. ES_HOST: $Env:ELASTICSEARCH_HOST"
  }
}
