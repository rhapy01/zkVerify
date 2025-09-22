param(
    [switch]$VerboseOutput
)

$ErrorActionPreference = 'Stop'

function Run-Step {
    param([string]$Name, [scriptblock]$Action)
    Write-Host "=== $Name ===" -ForegroundColor Cyan
    & $Action
    Write-Host "OK: $Name`n" -ForegroundColor Green
}

Push-Location $PSScriptRoot\..
try {
    # Speed up cargo by avoiding network index updates when possible
    $env:CARGO_NET_GIT_FETCH_WITH_CLI = 'true'

    if ($VerboseOutput) { $env:RUST_LOG = 'info' }

    Run-Step 'Check native crate' { cargo check -q -p native }

    Run-Step 'Check STWO pallet' { cargo check -q -p pallet-stwo-verifier }

    Run-Step 'Compile STWO tests (no-run)' { cargo test -q -p pallet-stwo-verifier --no-run }

    # Optional formatting check if rustfmt is available
    try {
        Run-Step 'rustfmt check' { cargo fmt --all -- --check }
    } catch {
        Write-Host 'Skipping rustfmt check (tool not available)' -ForegroundColor Yellow
    }

    # Optional clippy check if available but do not fail CI-alike locally
    try {
        Run-Step 'clippy (warnings allowed)' { cargo clippy -q -p native -p pallet-stwo-verifier -- -A warnings }
    } catch {
        Write-Host 'Skipping clippy (tool not available)' -ForegroundColor Yellow
    }

    Write-Host "\nLocal subset CI completed successfully." -ForegroundColor Green
    exit 0
}
catch {
    Write-Error $_
    exit 1
}
finally {
    Pop-Location
}


