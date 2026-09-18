function ess_up {
  param (
      [string]$StackVersion,
      [string]$StackBuildId
  )

  Write-Output "~~~ Starting ESS Stack"

  if (-not $StackVersion) {
      Write-Error "Error: Specify stack version: ess_up [stack_version] [stack_build_id]"
      return 1
  }

  # Write parameters to a JSON file and pass via --parameters-file.
  # Windows PowerShell 5.1 mangles native-command arguments that contain
  # embedded double quotes (even when passed as a separate argument), so
  # the inline --parameters form produced "invalid character 'G'" errors
  # from oblt-cli. A file bypasses PS arg marshalling entirely.
  $paramsPath      = Join-Path $PWD "params.json"
  $clusterInfoPath = Join-Path $PWD "cluster-info.json"
  $params = @{
      StackVersion     = $StackVersion
  }

  if ($Env:INTEGRATION_SERVER_DOCKER_IMAGE) {
      $params.ElasticAgentDockerImage = $Env:INTEGRATION_SERVER_DOCKER_IMAGE
  }

  # Snapshot stacks need explicit image tags. Released stacks can be created
  # from StackVersion alone until the next snapshot build is available.
  if ($StackBuildId) {
      $params.StackBuildId = "$StackBuildId"
  }

  $params | ConvertTo-Json -Compress | Set-Content -Path $paramsPath -Encoding ASCII

  try {
    # --output-file must be an absolute path; oblt-cli resolves relative
    # paths against its own config dir (~/.oblt-cli), not CWD.
    & oblt-cli cluster create custom `
        --template ess-ea-it-build-id `
        --cluster-name-prefix hosted `
        --parameters-file $paramsPath `
        --parameter "ExpireInHours=4" `
        --output-file $clusterInfoPath `
        --wait 20
  } finally {
    Remove-Item -Path $paramsPath -Force -ErrorAction SilentlyContinue
  }
  if ($LASTEXITCODE -ne 0) {
      Write-Error "Error: oblt-cli cluster create custom failed (exit=$LASTEXITCODE)"
      return 1
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

  # However, store retry cluster names in a separate metadata key so they can
  # be cleaned up by a dedicated cleanup step if the finally block fails (e.g., timeout)
  if ($Env:BUILDKITE_RETRY_COUNT -and $Env:BUILDKITE_RETRY_COUNT -gt 0) {
      $MetadataPrefix = if ($Env:FIPS -eq "true") { "fips." } else { "" }
      $retryKey = "${MetadataPrefix}retry-cluster-$($Env:BUILDKITE_STEP_ID)-$($Env:BUILDKITE_RETRY_COUNT)"
      Write-Output "Storing retry cluster name in metadata: $retryKey = $ClusterName"
      & buildkite-agent meta-data set $retryKey $ClusterName
  }

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
      $ClusterName = Get-EssClusterNameFromMetadata
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

# True when oblt-cli failed because GCP Secret Manager does not have the
# cluster env secret yet (gRPC NotFound). Other failures should not be polled.
function Test-EssSecretsNotFoundYet {
  param([string]$Output)
  return $Output -match '(?i)code = NotFound|not found or has no versions'
}

# Runs a native command and returns its exit code, its stdout, and its combined
# stdout/stderr as strings.
#
# Redirecting the stderr of a native command (`2>&1`, `2>$null`, ...) makes
# PowerShell wrap every stderr line in a NativeCommandError record. The
# Buildkite agent runs job commands through a wrapper that sets
# `$ErrorActionPreference = "STOP"`, which turns the first such record into a
# terminating error - even for a command that goes on to succeed. oblt-cli logs
# everything, including `[info]` lines, to stderr, so it always tripped this.
# Relax the preference for the duration of the call and flatten the records
# back into strings.
function Invoke-NativeCommand {
  param(
    [string]$FilePath,
    [string[]]$ArgumentList = @()
  )

  $previousPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $captured = & $FilePath @ArgumentList 2>&1
  } finally {
    $ErrorActionPreference = $previousPreference
  }
  $exitCode = $LASTEXITCODE

  # Merged stderr arrives as ErrorRecord objects, stdout as plain strings.
  $stdOut = [System.Collections.Generic.List[string]]::new()
  $combined = [System.Collections.Generic.List[string]]::new()
  foreach ($item in $captured) {
    $line = "$item"
    if ($item -isnot [System.Management.Automation.ErrorRecord]) {
      $stdOut.Add($line)
    }
    $combined.Add($line)
  }

  return [pscustomobject]@{
    ExitCode = $exitCode
    StdOut   = ($stdOut -join [Environment]::NewLine)
    Output   = ($combined -join [Environment]::NewLine)
  }
}

# Reads the shared cluster name from Buildkite meta-data, or $null when unset.
function Get-EssClusterNameFromMetadata {
  $metadata = Invoke-NativeCommand -FilePath 'buildkite-agent' -ArgumentList @('meta-data', 'get', 'cluster-name')
  if ($metadata.ExitCode -ne 0) {
    return $null
  }
  return $metadata.StdOut.Trim()
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
    $ClusterName = Get-EssClusterNameFromMetadata
  }
  if (-not $ClusterName) {
    Write-Error "Error: no cluster-name available (neither cluster-info.json nor meta-data); cannot load secrets."
    return 1
  }

  # `oblt-cli cluster create --wait` returns as soon as the cluster config lands
  # on the observability-test-environments default branch, but the credentials
  # secret is published by a later step of the cluster-manager workflow and has
  # been observed to lag by several minutes. Poll rather than reading it once.
  $timeoutSeconds = if ($Env:ESS_SECRETS_TIMEOUT_SECONDS) { [int]$Env:ESS_SECRETS_TIMEOUT_SECONDS } else { 600 }
  $intervalSeconds = if ($Env:ESS_SECRETS_POLL_INTERVAL_SECONDS) { [int]$Env:ESS_SECRETS_POLL_INTERVAL_SECONDS } else { 15 }

  # --output-file must be absolute (oblt-cli resolves relative paths against
  # its own config dir). Capture output so retry attempts stay to one line
  # and don't pollute the function's return value captured by `$rc =
  # ess_load_secrets` in the caller. Dump the last oblt-cli output only when
  # giving up. Retry only GCP NotFound (secret not published yet); fail fast
  # on auth, permission, or other errors.
  $envFile = Join-Path $PWD "secrets.env"
  $deadline = (Get-Date).AddSeconds($timeoutSeconds)
  $attempt = 0
  while ($true) {
    $attempt++
    $result = Invoke-NativeCommand -FilePath 'oblt-cli' -ArgumentList @(
      'cluster', 'secrets', 'env',
      '--cluster-name', $ClusterName,
      '--output-file', $envFile
    )
    $lastExit = $result.ExitCode
    $lastOutput = $result.Output
    if ($lastExit -eq 0) {
      if ($lastOutput.Trim()) {
        Write-Host $lastOutput
      }
      break
    }
    if (-not (Test-EssSecretsNotFoundYet $lastOutput)) {
      Write-Host $lastOutput
      Write-Error "Error: oblt-cli cluster secrets env failed for cluster '$ClusterName' (exit=$lastExit); not retrying"
      return 1
    }
    if ((Get-Date) -ge $deadline) {
      Write-Host $lastOutput
      Write-Error "Error: oblt-cli cluster secrets env failed for cluster '$ClusterName' after ${timeoutSeconds}s and $attempt attempts (last exit=$lastExit)"
      return 1
    }
    Write-Host "Secrets for cluster '$ClusterName' are not available yet (attempt $attempt, exit=$lastExit); retrying in ${intervalSeconds}s..."
    Start-Sleep -Seconds $intervalSeconds
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
      [string]$StackVersion,
      [string]$StackBuildId
  )

  if ($Env:BUILDKITE_RETRY_COUNT -gt 0) {
      Write-Output "The step is retried, starting the ESS stack again"
      ess_up $StackVersion $StackBuildId
  }
}
