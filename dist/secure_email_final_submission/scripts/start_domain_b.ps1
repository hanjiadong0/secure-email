$RepoRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$Config = Join-Path $RepoRoot "configs\domainB.yaml"

if (-not (Test-Path $Python)) {
    Write-Error "Virtual environment python not found at $Python. Create it first with: python -m venv .venv"
    exit 1
}

Push-Location $RepoRoot
try {
    & $Python -m server.main --config $Config
} finally {
    Pop-Location
}
