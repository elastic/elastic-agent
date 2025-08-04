$cpuArch = $env:PROCESSOR_ARCHITECTURE.ToLower()
$goBasePath = "C:\Users\Buildkite\.go"

function installGoBinary {
    param (
        [string]$Version
    )

    pushd $goBasePath

    # prevent Invoke-WebRequest error: The request was aborted: Could not create SSL/TLS secure channel. on older Windows versions
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # suppress progress output which can slow down downloading and extracting archives *A LOT* (mins vs seconds)
    $global:ProgressPreference = "SilentlyContinue"

    Write-Host "Downloading go version: ${Version}"

    Retry-Command -scriptBlock {
        Invoke-WebRequest -Uri https://go.dev/dl/go${Version}.windows-${cpuArch}.zip -Outfile go${Version}.zip
    }
    Write-Host "Extracting: go${Version}.zip"
    Expand-Archive -Path go${Version}.zip -DestinationPath .
    # official Windows Go zip archives package files have a go\ top level dir -- we rename this to our preferred go-<version> convention
    Move-Item go go-${Version} -Force
    Write-Host "Deployed go ${Version} under ${goBasePath}\go-${Version}"
    Remove-Item go${Version}.zip
    popd
}

if (Test-Path ".go-version") {
    $GoVersion = Get-Content -Path .go-version

    $GOROOT = "${goBasePath}\go-$GoVersion"
    $GOPATH = "$GOROOT\packages"
    $GOBIN = "$GOROOT\bin"

    if (-not (Test-Path -Path $GOROOT -PathType Container)) {
        Write-Host "~~~ Repo requires Go: $GoVersion but it's not pre-installed on the VM image. Installing ... "
        installGoBinary -Version $GoVersion
    }    

    Write-Host "~~~ Enabled go version: $GoVersion, GOBIN is: $GOBIN, GOPATH is: $GOPATH"

    $env:GOPATH=$GOPATH
    $env:GOROOT=$GOROOT
    $env:GOBIN=$GOBIN
    $env:Path = "$GOBIN;" + "$GOPATH\bin;" + $env:Path

    if ($null -eq (Get-Command "mage.exe" -ErrorAction SilentlyContinue)) {
        # TODO programmatically grab from beats repo
        $MAGE_VERSION = "1.15.0"
        go install "github.com/magefile/mage@v${MAGE_VERSION}"
        Write-Host "~~~ Installed mage v${MAGE_VERSION}"
    }
} else {
    Write-Host "+++ Warning! Didn't find a valid .go-version file in the checkout. A go environment will not be available."
}

#it looks like windows images in combination with buildkite-agent dont export %USERPROFILE% and for this reason the 
# MAGEFILE_CACHE is not properly interpolated
$env:MAGEFILE_CACHE="C:\Users\Buildkite\.magefile"
