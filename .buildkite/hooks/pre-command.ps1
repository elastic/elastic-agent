# Shorten BUILDKITE_MESSAGE if needed to avoid filling the Windows env var buffer
$env:BUILDKITE_MESSAGE = $env:BUILDKITE_MESSAGE.Substring(0, [System.Math]::Min(2048, $env:BUILDKITE_MESSAGE.Length))

# Configure GOCACHEPROG (https://github.com/platacard/cacheprog) so the Go build
# cache lives in S3. Steps opt in by adding the elastic/oblt-aws-auth plugin,
# which provides the AWS credentials. Keep in sync with
# .buildkite/scripts/setup-cacheprog.sh. On any failure GOCACHEPROG stays unset
# and Go falls back to the local GOCACHE.
if ($env:BUILDKITE_PLUGINS -like "*oblt-aws-auth*") {
  $cacheprogVersion = "v1.3.0"
  Write-Host "--- Setting up cacheprog $cacheprogVersion for the Go build cache"
  try {
    switch ($env:PROCESSOR_ARCHITECTURE) {
      "AMD64" { $arch = "amd64"; $sha256 = "237b3d18b75cdc03b3245ba689a689d05bcc0a0c5cd5400010ec9fd14ae5fae0" }
      "ARM64" { $arch = "arm64"; $sha256 = "1c9fcca48a3f790b8357513f183ef4fe126fa5e9a4fd1ced7e433aac70d489de" }
      default { throw "unsupported architecture $($env:PROCESSOR_ARCHITECTURE)" }
    }
    $dir = Join-Path $env:TEMP "cacheprog-$cacheprogVersion"
    $bin = Join-Path $dir "cacheprog.exe"
    if (-not (Test-Path $bin)) {
      New-Item -ErrorAction Stop -ItemType Directory -Force -Path $dir | Out-Null
      $archive = Join-Path $dir "cacheprog_${cacheprogVersion}_windows_${arch}.zip"
      $ProgressPreference = "SilentlyContinue"
      Invoke-WebRequest -ErrorAction Stop -UseBasicParsing -OutFile $archive `
        -Uri "https://github.com/platacard/cacheprog/releases/download/$cacheprogVersion/cacheprog_${cacheprogVersion}_windows_${arch}.zip"
      if ((Get-FileHash -Algorithm SHA256 $archive).Hash -ne $sha256) {
        throw "checksum mismatch"
      }
      Expand-Archive -ErrorAction Stop -Force -Path $archive -DestinationPath $dir
      Remove-Item $archive
    }

    # Anything cacheprog writes to stderr ends up in the output of every `go`
    # command, which breaks tests that inspect `go test` output. The wrapper
    # sends it to a file instead (--log-output is broken in v1.3.0, it still
    # logs to stderr), and disables automemlimit, which logs an error when
    # there are no cgroups to derive GOMEMLIMIT from. AUTOMEMLIMIT is set only
    # for cacheprog because EDOT components under test use the same library.
    $log = Join-Path $dir "cacheprog.log"
    $wrapper = Join-Path $dir "cacheprog-wrapper.cmd"
    Set-Content -ErrorAction Stop -Encoding ascii -Path $wrapper -Value @(
      "@echo off",
      "set AUTOMEMLIMIT=off",
      "`"$bin`" %* 2>>`"$log`""
    )

    $env:GOCACHEPROG = $wrapper
    $env:CACHEPROG_REMOTE_STORAGE_TYPE = "s3"
    $env:CACHEPROG_S3_BUCKET = "elastic-agent-ci-go-cache"
    $env:CACHEPROG_S3_REGION = "us-east-1"
    $env:CACHEPROG_S3_PREFIX = "cacheprog-poc"
    $env:CACHEPROG_S3_EXPIRATION = "24h"
    $env:CACHEPROG_ROOT_DIRECTORY = Join-Path $dir "disk"
    Write-Host "GOCACHEPROG=$env:GOCACHEPROG"
  } catch {
    Write-Host "cacheprog: setup failed ($_), falling back to the local GOCACHE"
  }
}
