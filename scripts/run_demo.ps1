$RepoRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$baseA = "http://127.0.0.1:8443"
$baseB = "http://127.0.0.1:9443"

function Invoke-Step {
    param(
        [string]$Description,
        [string[]]$Arguments,
        [switch]$AllowFailure
    )

    Write-Host "==> $Description"
    & $Python @Arguments
    if ($LASTEXITCODE -ne 0 -and -not $AllowFailure) {
        throw "Step failed: $Description"
    }
    if ($LASTEXITCODE -ne 0 -and $AllowFailure) {
        Write-Host "Continuing after non-fatal failure: $Description"
    }
}

if (-not (Test-Path $Python)) {
    Write-Error "Virtual environment python not found at $Python. Create it first with: python -m venv .venv"
    exit 1
}

try {
    Invoke-WebRequest -Uri "$baseA/health" -UseBasicParsing | Out-Null
    Invoke-WebRequest -Uri "$baseB/health" -UseBasicParsing | Out-Null
} catch {
    Write-Error "Start both servers first with scripts/start_domain_a.ps1 and scripts/start_domain_b.ps1."
    exit 1
}

Push-Location $RepoRoot
try {
    Invoke-Step "Register Alice" @("-m", "client.cli", "--base-url", $baseA, "register", "--email", "alice@a.test", "--password", "demo123", "--confirm-password", "demo123") -AllowFailure
    Invoke-Step "Register Bob" @("-m", "client.cli", "--base-url", $baseB, "register", "--email", "bob@b.test", "--password", "demo123", "--confirm-password", "demo123") -AllowFailure
    Invoke-Step "Login Alice" @("-m", "client.cli", "--base-url", $baseA, "login", "--email", "alice@a.test", "--password", "demo123")
    Invoke-Step "Login Bob" @("-m", "client.cli", "--base-url", $baseB, "login", "--email", "bob@b.test", "--password", "demo123")
    Invoke-Step "Send cross-domain mail" @("-m", "client.cli", "--base-url", $baseA, "send", "--email", "alice@a.test", "--to", "bob@b.test", "--subject", "Demo Mail", "--body", "Can we meet tomorrow?")
    Start-Sleep -Seconds 1
    Invoke-Step "Fetch Bob inbox" @("-m", "client.cli", "--base-url", $baseB, "inbox", "--email", "bob@b.test")
} finally {
    Pop-Location
}
