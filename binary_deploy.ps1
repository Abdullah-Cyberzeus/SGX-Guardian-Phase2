$ScriptPath = Join-Path $PSScriptRoot "scripts/binary_deploy.ps1"
& $ScriptPath @args
exit $LASTEXITCODE
