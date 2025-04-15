choco install mise
New-Item -ItemType Directory -Path "$HOME\Documents\PowerShell"
echo 'mise activate pwsh | Out-String | Invoke-Expression' >> $HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1
