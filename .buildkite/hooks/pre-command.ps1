# Install gvm and go
$env:GvmVersion = "0.5.2"
$Env:GOTMPDIR = $Env:BUILDKITE_BUILD_CHECKOUT_PATH #https://github.com/golang/go/issues/42224#issuecomment-1021149948
[Net.ServicePointManager]::SecurityProtocol = "tls12"
$env:GoVersion = Get-Content -Path .go-version
Invoke-WebRequest -URI https://github.com/andrewkroh/gvm/releases/download/v$env:GvmVersion/gvm-windows-amd64.exe -Outfile C:\Windows\System32\gvm.exe
gvm --format=powershell $env:GoVersion | Invoke-Expression
go version

# Install tools
go install github.com/magefile/mage
go install github.com/elastic/go-licenser
go install golang.org/x/tools/cmd/goimports
go install github.com/jstemmer/go-junit-report
go install gotest.tools/gotestsum

# debug
Write-Host "GOPATH: $env:GOPATH"
Get-ChildItem -Path $env:GOPATH\bin
