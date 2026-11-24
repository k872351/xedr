param(
    [string]$OutputDir = (Join-Path $env:TEMP "edr-agent-matrix"),
    [switch]$IncludeDarwin
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$AgentDir = Join-Path $RepoRoot "agent"
$Targets = @(
    @{ GOOS = "windows"; GOARCH = "amd64" },
    @{ GOOS = "windows"; GOARCH = "386" },
    @{ GOOS = "windows"; GOARCH = "arm64" },
    @{ GOOS = "linux"; GOARCH = "amd64" },
    @{ GOOS = "linux"; GOARCH = "arm64" },
    @{ GOOS = "linux"; GOARCH = "loong64" },
    @{ GOOS = "linux"; GOARCH = "riscv64" }
)
if ($IncludeDarwin) {
    $Targets += @(
        @{ GOOS = "darwin"; GOARCH = "amd64" },
        @{ GOOS = "darwin"; GOARCH = "arm64" }
    )
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$OldGoos = $env:GOOS
$OldGoarch = $env:GOARCH
$OldCGO = $env:CGO_ENABLED
$env:CGO_ENABLED = "0"
$Failed = [System.Collections.Generic.List[string]]::new()

try {
    Push-Location $AgentDir
    try {
        Write-Host "Go toolchain: $(go version)"
        foreach ($Target in $Targets) {
            $Label = "$($Target.GOOS)-$($Target.GOARCH)"
            $env:GOOS = $Target.GOOS
            $env:GOARCH = $Target.GOARCH
            $Suffix = if ($Target.GOOS -eq "windows") { ".exe" } else { "" }
            $Output = Join-Path $OutputDir "forensic-agent-$Label$Suffix"
            Write-Host "[build] $Label"
            & go build -trimpath -o $Output .
            if ($LASTEXITCODE -ne 0) {
                $Failed.Add($Label)
                Remove-Item -LiteralPath $Output -Force -ErrorAction SilentlyContinue
                continue
            }
            if ($Target.GOOS -eq "windows") {
                $SetupOutput = Join-Path $OutputDir "forensic-agent-setup-$Label.exe"
                & go build -trimpath -o $SetupOutput ./cmd/setup
                if ($LASTEXITCODE -ne 0) {
                    $Failed.Add("$Label setup")
                    Remove-Item -LiteralPath $SetupOutput -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    $env:GOOS = $OldGoos
    $env:GOARCH = $OldGoarch
    $env:CGO_ENABLED = $OldCGO
}

if ($Failed.Count -gt 0) {
    Write-Error "Agent build matrix failed: $($Failed -join ', ')"
    exit 1
}
Write-Host "Agent build matrix passed. Artifacts: $OutputDir"
