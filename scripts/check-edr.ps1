param(
    [switch]$FullAgentTests,
    [switch]$SkipFrontend,
    [switch]$SkipAgent
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Failures = [System.Collections.Generic.List[string]]::new()

function Invoke-Check {
    param([string]$Name, [string]$Directory, [scriptblock]$Run)
    Write-Host "[CHECK] $Name"
    Push-Location $Directory
    try {
        & $Run
        if ($LASTEXITCODE -ne 0) { throw "Exit code $LASTEXITCODE" }
        Write-Host "[PASS] $Name"
    } catch {
        $Failures.Add($Name)
        Write-Warning "$Name failed: $_"
    } finally {
        Pop-Location
    }
}

Invoke-Check 'Python dependency consistency' $ProjectRoot { python -m pip check }
Invoke-Check 'Python direct dependency pins' $ProjectRoot { python scripts/check_dependency_versions.py }
Invoke-Check 'CI change-mapping self-test' $ProjectRoot { python scripts/detect_changes.py --self-test }
Invoke-Check 'CHANGELOG gate self-test' $ProjectRoot { python scripts/check_changelog.py --self-test }
Invoke-Check 'Backend regression suite' $ProjectRoot { python -m unittest discover -s backend -t . -p 'test_*.py' -v }
if (-not $SkipAgent) {
    Invoke-Check 'Agent health compatibility' (Join-Path $ProjectRoot 'agent') { go test -run '^(TestCaptureHealthScore|TestResourceCPUSample|TestComponentHealthState|TestDiagnosticTiming|TestNativeResourceLayout)' -count=1 }
    Invoke-Check 'Linux package inventory parsers' (Join-Path $ProjectRoot 'agent') { go test -run '^(TestDpkgInventory|TestRPMInventory)$' -count=1 }
    Invoke-Check 'Existing release integrity' $ProjectRoot { python scripts/verify_release.py agent/build-manifest.json }
    if ($FullAgentTests) {
        Invoke-Check 'Agent full test suite' (Join-Path $ProjectRoot 'agent') { go test ./... -count=1 }
    }
}
if (-not $SkipFrontend) {
    Invoke-Check 'Frontend regression suite' (Join-Path $ProjectRoot 'agent_admin') { npm test }
    Invoke-Check 'Frontend production build' (Join-Path $ProjectRoot 'agent_admin') { npm run build }
}

if ($Failures.Count -gt 0) {
    Write-Warning ('Failed checks: ' + ($Failures -join ', '))
    exit 1
}
Write-Host 'All selected checks passed.'
