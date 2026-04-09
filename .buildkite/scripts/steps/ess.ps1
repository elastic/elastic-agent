function ess_up {
  param (
      [string]$StackVersion
  )

  Write-Output "~~~ Starting ESS Stack"

  if (-not $StackVersion) {
      Write-Error "Error: Specify stack version: ess_up [stack_version]"
      return 1
  }

  & oblt-cli cluster create custom `
      --template ess-ea-it `
      --cluster-name-prefix ea-hosted-it `
      --parameters="{`"GitOps`":`"true`",`"GitHubRepository`":`"$Env:BUILDKITE_REPO`",`"GitHubCommit`":`"$Env:BUILDKITE_COMMIT`",`"EphemeralCluster`":`"true`",`"StackVersion`":`"$StackVersion`"}" `
      --output-file="cluster-info.json" `
      --wait 15

  $ClusterName = (Get-Content -Path "cluster-info.json" | ConvertFrom-Json).ClusterName
  if (-not $ClusterName) {
      Write-Error "Error: Failed to retrieve cluster name from cluster-info.json"
      return 1
  }

  # Store the cluster name as meta-data
  & buildkite-agent meta-data set cluster-name $ClusterName

  ess_load_secrets
}

function ess_down {
  Write-Output "~~~ Tearing down the ESS Stack"
  try {
    $ClusterName = & buildkite-agent meta-data get cluster-name
    & oblt-cli cluster destroy --cluster-name "$ClusterName" --force
  } catch {
    Write-Output "Error: Failed to destroy ESS stack(it will be auto-deleted later): $_"
  }
}

function ess_load_secrets {
  Write-Output "~~~ Loading ESS Stack secrets"

  $ClusterName = & buildkite-agent meta-data get cluster-name
  & oblt-cli cluster secrets env --cluster-name $ClusterName --output-file="secrets.env"

  $envFile = "secrets.env"
  if (Test-Path $envFile) {
      Get-Content $envFile | ForEach-Object {
          if ($_ -match '^export\s+(.+?)=(.+)$') {
              $name = $matches[1].Trim()
              $value = $matches[2].Trim('"', "'", ' ')
              [System.Environment]::SetEnvironmentVariable($name, $value)
              Write-Output "Set environment variable: $name"
          } elseif ($_ -match '^(.+?)=(.+)$') {
              $name = $matches[1].Trim()
              $value = $matches[2].Trim('"', "'", ' ')
              [System.Environment]::SetEnvironmentVariable($name, $value)
              Write-Output "Set environment variable: $name"
          }
      }
      Write-Output "Environment variables loaded successfully from $envFile"
      Remove-Item -Path $envFile -Force -ErrorAction Stop
  } else {
      Write-Error "secrets.env file not found at $envFile"
      return 1
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

function Get-Ess-Stack {
  param (
      [string]$StackVersion
  )

  if ($Env:BUILDKITE_RETRY_COUNT -gt 0) {
      Write-Output "The step is retried, starting the ESS stack again"
      ess_up $StackVersion
  }
}
