# Build DataProtector.sys (GPL-3.0, vendored from EDR-DataProtector) with cl/link directly,
# because this machine has the WDK headers/libs but no WDK MSBuild integration.
# Usage:  powershell -ExecutionPolicy Bypass -File build.ps1 [-NoSign]
param([switch]$NoSign, [string]$OutDir = "")

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $OutDir) { $OutDir = Join-Path $Root "out" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) { throw "VS C++ build tools not found" }
$vsDev = Join-Path $vsPath "Common7\Tools\VsDevCmd.bat"

$kitBase = "${env:ProgramFiles(x86)}\Windows Kits\10"
$ver = Get-ChildItem "$kitBase\Include" -Directory | Where-Object { Test-Path (Join-Path $_.FullName "km\fltKernel.h") } |
  Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty Name
if (-not $ver) { throw "WDK with km\fltKernel.h not found" }
$inc = "$kitBase\Include\$ver"
$lib = "$kitBase\Lib\$ver\km\x64"

$sources = Get-ChildItem $Root -Filter *.c | ForEach-Object { $_.FullName }
$defs = "/D_AMD64_ /DAMD64 /D_WIN64 /DWIN64 /DNTDDI_VERSION=0x0A000008 /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 " +
        "/DPOOL_NX_OPTIN=1 /DNDIS630=1 /DNDIS_SUPPORT_NDIS630=1 /DDEPRECATE_DDK_FUNCTIONS=1 /DNDEBUG"
# /we4013: implicit function declaration is an error (on x64 it silently truncates returned pointers)
$cflags = "/nologo /c /kernel /utf-8 /W3 /we4013 /we4047 /we4024 /O2 /GS- /Gy /Zi /Zp8 /GR- /EHs-c- /Gz"
$incs = "/I`"$Root`" /I`"$inc\km`" /I`"$inc\shared`" /I`"$inc\km\crt`""

$lines = @('@echo off', "call `"$vsDev`" -arch=amd64 -host_arch=amd64 >nul")
$objs = @()
foreach ($c in $sources) {
  $o = Join-Path $OutDir ([IO.Path]::GetFileNameWithoutExtension($c) + ".obj")
  $objs += "`"$o`""
  $lines += "cl $cflags $defs $incs `"$c`" /Fo`"$o`" /Fd`"$OutDir\dataprotector.pdb`""
  $lines += 'if errorlevel 1 exit /b 1'
}
$sys = Join-Path $OutDir "DataProtector.sys"
$libs = "ntoskrnl.lib hal.lib fltmgr.lib fwpkclnt.lib ndis.lib netio.lib ksecdd.lib cng.lib wdmsec.lib"
$lines += "link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB /INTEGRITYCHECK /RELEASE /DEBUG " +
          "/MERGE:_TEXT=.text /SECTION:INIT,d /OPT:REF /OPT:ICF /LIBPATH:`"$lib`" $libs " +
          "/OUT:`"$sys`" /PDB:`"$OutDir\DataProtector_sys.pdb`" $($objs -join ' ')"
$lines += 'if errorlevel 1 exit /b 1'
$lines += 'exit /b 0'

$bat = Join-Path $env:TEMP "dp-build.bat"
Set-Content -Path $bat -Value ($lines -join "`r`n") -Encoding ASCII
& cmd /c $bat
$rc = $LASTEXITCODE
Remove-Item $bat -Force -ErrorAction SilentlyContinue
if ($rc -ne 0 -or -not (Test-Path $sys)) { throw "build failed (rc=$rc)" }
Write-Host "[OK] $sys ($([math]::Round((Get-Item $sys).Length/1KB,1)) KB)"

if ($NoSign) { exit 0 }
$signtool = Get-ChildItem "$kitBase\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
  Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
if (-not $signtool) { throw "signtool.exe not found" }
$subject = "CN=XEDR Driver Test Signing"
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object Subject -eq $subject | Select-Object -First 1
if (-not $cert) {
  $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject -CertStoreLocation Cert:\CurrentUser\My `
    -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(5)
}
$cer = Join-Path $OutDir "XEDRDriverTest.cer"
Export-Certificate -Cert $cert -FilePath $cer -Force | Out-Null
& $signtool sign /fd sha256 /sha1 $cert.Thumbprint /s My "$sys"
if ($LASTEXITCODE -ne 0) { throw "signtool failed" }
Copy-Item (Join-Path $Root "DataProtector.inf") (Join-Path $OutDir "DataProtector.inf") -Force
Write-Host "[OK] test-signed; cert: $cer"
