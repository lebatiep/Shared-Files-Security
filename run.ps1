$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$appPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $appPython)) {
    py -3.12 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Install Python 3.12 or newer before running the app.' }
}
& $appPython -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Could not install application dependencies.' }
& $appPython -m secure_share
exit $LASTEXITCODE
