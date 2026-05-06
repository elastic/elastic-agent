function ess_up {
  param (
      [string]$StackVersion
  )

  Write-Output "~~~ Starting ESS Stack"

  if (-not $StackVersion) {
      Write-Error "Error: Specify stack version: ess_up [stack_version]"
      return 1
  }

  # Write parameters to a JSON file and pass via --parameters-file.
  # Windows PowerShell 5.1 mangles native-command arguments that contain
  # embedded double quotes (even when passed as a separate argument), so
  # the inline --parameters form produced "invalid character 'G'" errors
  # from oblt-cli. A file bypasses PS arg marshalling entirely.
  $paramsPath      = Join-Path $PWD "params.json"
  $clusterInfoPath = Join-Path $PWD "cluster-info.json"
  @{
      GitOps           = "true"
      GitHubRepository = $Env:BUILDKITE_REPO
      GitHubCommit     = $Env:BUILDKITE_COMMIT
      EphemeralCluster = "true"
      StackVersion     = $StackVersion
  } | ConvertTo-Json -Compress | Set-Content -Path $paramsPath -Encoding ASCII

  try {
    # --output-file must be an absolute path; oblt-cli resolves relative
    # paths against its own config dir (~/.oblt-cli), not CWD.
    & oblt-cli cluster create custom `
        --template ess-ea-it `
        --cluster-name-prefix ea-hosted-it `
        --parameters-file $paramsPath `
        --output-file $clusterInfoPath `
        --wait 20
  } finally {
    Remove-Item -Path $paramsPath -Force -ErrorAction SilentlyContinue
  }
  # fallback to check if secrets are available in case the cluster was created
  # but wait timed out (e.g. due to slow cluster creation or transient oblt-cli issues)
  if ($LASTEXITCODE -ne 0) {
      if (Test-Path $clusterInfoPath) {
          $ClusterName = (Get-Content -Path $clusterInfoPath | ConvertFrom-Json).ClusterName
          if ($ClusterName) {
              & oblt-cli cluster secrets env --cluster-name $ClusterName --output-file nul
              if ($LASTEXITCODE -eq 0) {
                  Write-Output "Cluster creation wait timed out, but secrets are available - continuing"
              } else {
                  Write-Error "Error: oblt-cli cluster create custom failed (exit=$LASTEXITCODE) and secrets check failed"
                  return 1
              }
          } else {
              Write-Error "Error: oblt-cli cluster create custom failed (exit=$LASTEXITCODE) and no cluster name found"
              return 1
          }
      } else {
          Write-Error "Error: oblt-cli cluster create custom failed (exit=$LASTEXITCODE)"
          return 1
      }
  }

  if (-not (Test-Path $clusterInfoPath)) {
      Write-Error "Error: cluster-info.json was not created by oblt-cli at $clusterInfoPath"
      return 1
  }

  $ClusterName = (Get-Content -Path $clusterInfoPath | ConvertFrom-Json).ClusterName
  if (-not $ClusterName) {
      Write-Error "Error: Failed to retrieve cluster name from cluster-info.json"
      return 1
  }

  # NOTE: the shared `cluster-name` meta-data is only written by the shared
  # ess_start_* wrapper. Per-step retries must not overwrite it, otherwise the
  # global cleanup step would destroy the retry's cluster and leak the shared
  # one. `ess_load_secrets` and `ess_down` read the local cluster-info.json
  # first, so the retry path doesn't need meta-data.

  $rc = ess_load_secrets
  if ($rc -ne 0) {
      Write-Error "Error: ess_load_secrets failed (exit=$rc)"
      return $rc
  }
}

function ess_down {
  Write-Output "~~~ Tearing down the ESS Stack"
  try {
    # Prefer the local cluster-info.json from this step's own ess_up,
    # so we don't destroy a cluster created by a parallel step.
    $ClusterName = $null
    $clusterInfoPath = Join-Path $PWD "cluster-info.json"
    if (Test-Path $clusterInfoPath) {
      $ClusterName = (Get-Content -Path $clusterInfoPath | ConvertFrom-Json).ClusterName
    }
    if (-not $ClusterName) {
      $ClusterName = & buildkite-agent meta-data get cluster-name 2>$null
    }
    if (-not $ClusterName) {
      Write-Output "No cluster-name found; nothing to destroy."
      return
    }
    & oblt-cli cluster destroy --cluster-name "$ClusterName" --force
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Failed to destroy cluster '$ClusterName' (exit=$LASTEXITCODE) - ephemeral cluster will auto-expire."
    }
  } catch {
    Write-Warning "Error during ess_down: $_ - ephemeral cluster will auto-expire."
  }
}

function ess_load_secrets {
  # Use Write-Host for informational output so callers that capture the return
  # value (e.g. `$rc = ess_load_secrets`) get a scalar exit code, not an array
  # of strings from the output stream.
  Write-Host "~~~ Loading ESS Stack secrets"

  # Prefer the local cluster-info.json from this step's own ess_up,
  # so we don't read secrets from a cluster created by a parallel step.
  $ClusterName = $null
  $clusterInfoPath = Join-Path $PWD "cluster-info.json"
  if (Test-Path $clusterInfoPath) {
    $ClusterName = (Get-Content -Path $clusterInfoPath | ConvertFrom-Json).ClusterName
  }
  if (-not $ClusterName) {
    $ClusterName = & buildkite-agent meta-data get cluster-name 2>$null
  }
  if (-not $ClusterName) {
    Write-Error "Error: no cluster-name available (neither cluster-info.json nor meta-data); cannot load secrets."
    return 1
  }

  # --output-file must be absolute (oblt-cli resolves relative paths against
  # its own config dir). Pipe stdout to Out-Host so it's visible in logs but
  # doesn't pollute the function's return value captured by `$rc =
  # ess_load_secrets` in the caller.
  $envFile = Join-Path $PWD "secrets.env"
  & oblt-cli cluster secrets env --cluster-name $ClusterName --output-file $envFile | Out-Host
  if ($LASTEXITCODE -ne 0) {
    Write-Error "Error: oblt-cli cluster secrets env failed (exit=$LASTEXITCODE)"
    return 1
  }

  if (-not (Test-Path $envFile)) {
      Write-Error "secrets.env file not found at $envFile"
      return 1
  }

  Get-Content $envFile | ForEach-Object {
      if ($_ -match '^export\s+(.+?)=(.+)$') {
          $name = $matches[1].Trim()
          $value = $matches[2].Trim('"', "'", ' ')
          [System.Environment]::SetEnvironmentVariable($name, $value)
          Write-Host "Set environment variable: $name"
      } elseif ($_ -match '^(.+?)=(.+)$') {
          $name = $matches[1].Trim()
          $value = $matches[2].Trim('"', "'", ' ')
          [System.Environment]::SetEnvironmentVariable($name, $value)
          Write-Host "Set environment variable: $name"
      }
  }
  Write-Host "Environment variables loaded successfully from $envFile"
  Remove-Item -Path $envFile -Force -ErrorAction Stop
  return 0
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
