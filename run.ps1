param(
    [switch]$Check,
    [switch]$UseDefaultData
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

# Prefer the project environment, then an installed Python with Tkinter.
$candidates = @((Join-Path $PSScriptRoot '.venv\Scripts\python.exe'))
foreach ($name in @('python', 'python3', 'py')) {
    $command = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue
    if ($command) { $candidates += $command.Source }
}
$appPython = $null
foreach ($candidate in ($candidates | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $detected = & $candidate -c 'import sys, tkinter; print(sys.executable) if sys.version_info >= (3, 12) else sys.exit(1)' 2>$null
    $probeExit = $LASTEXITCODE
    $ErrorActionPreference = $previousPreference
    if ($probeExit -eq 0 -and $detected) {
        $appPython = ($detected | Select-Object -Last 1).Trim()
        break
    }
}
if (-not $appPython) {
    throw 'Python 3.12 or newer with Tkinter is required. Install Python, then try again.'
}

Write-Host "Python: $appPython"
$launchArgs = @('-m', 'tools.launch')
if ($Check) { $launchArgs += '--check' }
if ($UseDefaultData) { $launchArgs += '--default-data' }
& $appPython @launchArgs
exit $LASTEXITCODE
