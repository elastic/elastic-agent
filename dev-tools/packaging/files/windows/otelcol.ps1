$workdir = Split-Path $MyInvocation.MyCommand.Path
& "$workdir\elastic-agent" otel $args