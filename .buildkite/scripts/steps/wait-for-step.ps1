# Waits for another step of the current build to finish, so that a job can do
# its own setup (VM boot, tool installation, building test binaries) in
# parallel with the step it needs artifacts from, instead of using depends_on.
#
# Usage: wait-for-step.ps1 -StepKey <step-key> [-TimeoutSeconds <seconds>]
#
# Exits 0 when the step passed, 1 when it failed or the timeout elapsed.
param (
    [Parameter(Mandatory = $true)][string]$StepKey,
    [int]$TimeoutSeconds = 3600,
    [int]$PollIntervalSeconds = 20
)

Write-Output "~~~ Waiting for step $StepKey to finish"
$start = Get-Date
while ($true) {
    # The attribute is only set once the step has finished; treat any error or
    # unknown value as "still running".
    $outcome = (& buildkite-agent step get outcome --step $StepKey 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        $outcome = ""
    }
    switch ($outcome) {
        "passed" {
            $elapsed = [int]((Get-Date) - $start).TotalSeconds
            Write-Output "Step $StepKey passed after ${elapsed}s"
            exit 0
        }
        { $_ -in "hard_failed", "soft_failed", "errored" } {
            Write-Error "Step $StepKey finished with outcome '$outcome'"
            exit 1
        }
    }
    if (((Get-Date) - $start).TotalSeconds -ge $TimeoutSeconds) {
        Write-Error "Timed out after ${TimeoutSeconds}s waiting for step $StepKey (last outcome: '$outcome')"
        exit 1
    }
    Start-Sleep -Seconds $PollIntervalSeconds
}
