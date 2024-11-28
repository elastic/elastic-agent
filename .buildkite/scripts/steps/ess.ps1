. "$PWD\.buildkite\scripts\retry.ps1"

function ess_up {
  param (
      [string]$StackVersion,
      [string]$EssRegion = "gcp-us-west2"
  )
  
  Write-Output "~~~ Starting ESS Stack"
  
  $Workspace = & git rev-parse --show-toplevel
  $TfDir = Join-Path -Path $Workspace -ChildPath "test_infra/ess/"

  if (-not $StackVersion) {
      Write-Error "Error: Specify stack version: ess_up [stack_version]"
      return 1
  }

  $Env:EC_API_KEY = Retry-Command -ScriptBlock {  
    vault kv get -field=apiKey kv/ci-shared/platform-ingest/platform-ingest-ec-prod
  }

  if (-not $Env:EC_API_KEY) {
      Write-Error "Error: Failed to get EC API key from vault"
      exit 1
  }

  $BuildkiteBuildCreator = if ($Env:BUILDKITE_BUILD_CREATOR) { $Env:BUILDKITE_BUILD_CREATOR } else { get_git_user_email }
  $BuildkiteBuildNumber = if ($Env:BUILDKITE_BUILD_NUMBER) { $Env:BUILDKITE_BUILD_NUMBER } else { "0" }
  $BuildkitePipelineSlug = if ($Env:BUILDKITE_PIPELINE_SLUG) { $Env:BUILDKITE_PIPELINE_SLUG } else { "elastic-agent-integration-tests" }

  Push-Location -Path $TfDir
  & terraform init
  & terraform apply -auto-approve `
      -var="stack_version=$StackVersion" `
      -var="ess_region=$EssRegion" `
      -var="creator=$BuildkiteBuildCreator" `
      -var="buildkite_id=$BuildkiteBuildNumber" `
      -var="pipeline=$BuildkitePipelineSlug"

  $Env:ELASTICSEARCH_HOST = & terraform output -raw es_host
  $Env:ELASTICSEARCH_USERNAME = & terraform output -raw es_username
  $Env:ELASTICSEARCH_PASSWORD = & terraform output -raw es_password
  $Env:KIBANA_HOST = & terraform output -raw kibana_endpoint
  $Env:KIBANA_USERNAME = $Env:ELASTICSEARCH_USERNAME
  $Env:KIBANA_PASSWORD = $Env:ELASTICSEARCH_PASSWORD
  Pop-Location
}

function ess_down {  
  $Workspace = & git rev-parse --show-toplevel
  $TfDir = Join-Path -Path $Workspace -ChildPath "test_infra/ess/"
  $stateFilePath = Join-Path -Path $TfDir -ChildPath "terraform.tfstate"

  if (-not (Test-Path -Path $stateFilePath)) {
    Write-Output "Terraform state file not found. Skipping ESS destroy."
    return 0
  }
  Write-Output "~~~ Tearing down the ESS Stack(created for this step)"
  try {  
    $Env:EC_API_KEY = Retry-Command -ScriptBlock {  
      vault kv get -field=apiKey kv/ci-shared/platform-ingest/platform-ingest-ec-prod
    }
    Push-Location -Path $TfDir
    & terraform init
    & terraform destroy -auto-approve
    Pop-Location
  } catch {
    Write-Output "Error: Failed to destroy ESS stack(it will be auto-deleted later): $_"
  }
}

function get_git_user_email {
  if (!(git rev-parse --is-inside-work-tree *>&1)) {
      return "unknown"
  }

  $email = & git config --get user.email

  if (-not $email) {
      return "unknown"
  } else {
      return $email
  }
}

function Get-Ess-Stack {
  param (
      [string]$StackVersion
  )
  
  if ($Env:BUILDKITE_RETRY_COUNT -gt 0) {
      Write-Output "The step is retried, starting the ESS stack again"        
      ess_up $StackVersion
      Write-Output "ESS stack is up. ES_HOST: $Env:ELASTICSEARCH_HOST"
  } else {
      # For the first run, we retrieve ESS stack metadata
      Write-Output "~~~ Receiving ESS stack metadata"
      $Env:ELASTICSEARCH_HOST = & buildkite-agent meta-data get "es.host"
      $Env:ELASTICSEARCH_USERNAME = & buildkite-agent meta-data get "es.username"
      $Env:ELASTICSEARCH_PASSWORD = & buildkite-agent meta-data get "es.pwd"
      $Env:KIBANA_HOST = & buildkite-agent meta-data get "kibana.host"
      $Env:KIBANA_USERNAME = & buildkite-agent meta-data get "kibana.username"
      $Env:KIBANA_PASSWORD = & buildkite-agent meta-data get "kibana.pwd"
      Write-Output "Received ESS stack data from previous step. ES_HOST: $Env:ELASTICSEARCH_HOST"
  }
}
