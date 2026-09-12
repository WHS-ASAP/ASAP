$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
py -3 -m asap web @args
exit $LASTEXITCODE
