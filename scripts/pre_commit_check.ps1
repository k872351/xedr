# 本地提交前质量门（借鉴 DataProtector package.json:101 simple-git-hooks）
#
# 说明：本项目当前目录不是 git 工作树（无 .git），因此不安装真实 git hook，
# 而是提供可直接运行的脚本；接入版本库后可按下文「接入 git hook」启用。
# 设计：只跑快速子集（秒级），完整门禁仍由 scripts/check-edr.ps1 -FullAgentTests 负责。
param(
    [switch]$IncludeGo,       # 额外跑 Go 全量测试（较慢）
    [switch]$IncludeFrontend, # 额外跑前端测试与构建（较慢）
    [switch]$StrictDiff       # 检查工作树是否有未提交改动（需 git 仓库）
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Failures = [System.Collections.Generic.List[string]]::new()

# 选择 Python：优先系统 Python（项目依赖装在这里），否则用 PATH 中的 python
$Python = $env:FORENSIC_PYTHON
if (-not $Python) {
    $candidate = 'C:\Users\Administrator\AppData\Local\Programs\Python\Python313\python.exe'
    if (Test-Path $candidate) { $Python = $candidate } else { $Python = 'python' }
}

function Invoke-Check {
    param([string]$Name, [scriptblock]$Run)
    Write-Host "[PRE-COMMIT] $Name"
    Push-Location $ProjectRoot
    try {
        & $Run
        if ($LASTEXITCODE -ne 0) { throw "exit code $LASTEXITCODE" }
        Write-Host "[PASS] $Name"
    } catch {
        $Failures.Add($Name)
        Write-Warning "$Name failed: $_"
    } finally {
        Pop-Location
    }
}

Invoke-Check 'Python dependency consistency' { & $Python -m pip check }
Invoke-Check 'Direct dependency pins' { & $Python scripts/check_dependency_versions.py }
Invoke-Check 'Backend regression (fast subset)' { & $Python -m unittest discover -s backend -t . -p 'test_*.py' }
Invoke-Check 'Rule replay' { & $Python tests/rule_replay/run_replay.py }
Invoke-Check 'Rule schema / compliance keys' { & $Python scripts/validate_rules.py }
Invoke-Check 'CI change-mapping self-test' { & $Python scripts/detect_changes.py --self-test }
Invoke-Check 'CHANGELOG gate self-test' { & $Python scripts/check_changelog.py --self-test }

if ($IncludeGo) {
    Invoke-Check 'Agent Go tests' { Push-Location (Join-Path $ProjectRoot 'agent'); try { & go test ./... -count=1 } finally { Pop-Location } }
}
if ($IncludeFrontend) {
    Invoke-Check 'Frontend tests + build' { Push-Location (Join-Path $ProjectRoot 'agent_admin'); try { & npm test; if ($LASTEXITCODE -ne 0) { return }; & npm run build } finally { Pop-Location } }
}
if ($StrictDiff) {
    # 对应 DataProtector 的 `git diff --exit-code`：确保格式化没留下未提交改动
    Invoke-Check 'No unstaged diff after formatting' { & git diff --exit-code }
}

if ($Failures.Count -gt 0) {
    Write-Warning ('Pre-commit FAILED: ' + ($Failures -join ', '))
    exit 1
}
Write-Host 'Pre-commit checks passed.'
Write-Host ''
Write-Host '接入 git hook（本项目接入版本库后）：'
Write-Host '  1) 在 .git/hooks/pre-commit 写入:'
Write-Host '     powershell -NoProfile -ExecutionPolicy Bypass -File scripts/pre_commit_check.ps1'
Write-Host '  2) 需要完整门禁时用: .\scripts\check-edr.ps1 -FullAgentTests'
