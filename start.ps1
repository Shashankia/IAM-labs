$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
Write-Host "Installing the lab's Python packages..."
python -m pip install -r requirements.txt
python -m helios @args
