# -*- coding: utf-8 -*-
"""用 WiX 3（tools/wix3）把 Setup.exe + forensic-agent.exe + agent.json 打成 ForensicAgent.msi。

安装：文件落到 %ProgramData%\\ForensicAgent\\pkg\\，再以 SYSTEM 执行
      ForensicAgent-Setup.exe /S /URL=[SERVERURL] 注册并启动服务。
卸载：执行 ForensicAgent-Setup.exe /U 停止并删除服务。
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from . import config

UPGRADE_CODE = "B7E2C1A0-4D5F-4E8A-9C3B-1A2D3E4F5A6B"


def wix_dir() -> Optional[Path]:
    d = Path(config.ROOT) / "tools" / "wix3"
    if (d / "candle.exe").is_file() and (d / "light.exe").is_file():
        return d
    return None


def _msi_version(version: str) -> str:
    nums = [int(x) for x in re.findall(r"\d+", str(version or ""))[:3]]
    while len(nums) < 3:
        nums.append(0)
    return ".".join(str(min(n, 255 if i == 0 else 65535)) for i, n in enumerate(nums))


def driver_files() -> list:
    """Production packages exclude the test-signed driver until separately verified."""
    return []


def sysmon_files() -> list:
    """仓库 Sysmon/ 下的二进制与 sysmonconfig-export.xml：随 MSI 落到 pkg\\sysmon\\。"""
    try:
        from . import agent_sysmon_artifact as asa
        return asa.iter_sysmon_bundle_files()
    except Exception:
        return []


def _sysmon_wix(files: list) -> tuple:
    if not files:
        return "", "", ""
    d = '          <Directory Id="SYSMONDIR" Name="sysmon" />\n'
    rows = []
    for i, p in enumerate(files):
        rows.append(
            f'      <Component Id="CmpSysmon{i}" Guid="*"><File Id="SysmonF{i}" Name="{p.name}" '
            f'Source="sysmon\\{p.name}" KeyPath="yes" /></Component>'
        )
    cmp = (
        '    <ComponentGroup Id="SysmonComponents" Directory="SYSMONDIR">\n'
        + "\n".join(rows)
        + "\n    </ComponentGroup>\n"
    )
    ref = '      <ComponentGroupRef Id="SysmonComponents" />\n'
    return d, cmp, ref


def _wxs(version: str, server_url: str, with_driver: bool, sysmon: list = None) -> str:
    url = server_url.replace('"', "")
    sm_dir, sm_cmp, sm_ref = _sysmon_wix(sysmon or [])
    driver_dir = (
        '          <Directory Id="DRIVERDIR" Name="driver" />\n' if with_driver else ""
    ) + sm_dir
    driver_cmp = (
        """    <ComponentGroup Id="DriverComponents" Directory="DRIVERDIR">
      <Component Id="CmpDpSys" Guid="*"><File Id="DpSys" Source="DataProtector.sys" KeyPath="yes" /></Component>
      <Component Id="CmpDpCer" Guid="*"><File Id="DpCer" Source="XEDRDriverTest.cer" KeyPath="yes" /></Component>
    </ComponentGroup>
"""
        if with_driver else ""
    )
    driver_ref = ('      <ComponentGroupRef Id="DriverComponents" />\n' if with_driver else "") + sm_ref
    driver_cmp = driver_cmp + sm_cmp
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="ForensicAgent" Language="1033" Version="{version}"
           Manufacturer="ForensicAgent" UpgradeCode="{UPGRADE_CODE}">
    <Package InstallerVersion="500" Compressed="yes" InstallScope="perMachine" InstallPrivileges="elevated" />
    <MajorUpgrade AllowSameVersionUpgrades="yes"
                  DowngradeErrorMessage="A newer version of ForensicAgent is already installed." />
    <MediaTemplate EmbedCab="yes" />
    <Property Id="SERVERURL" Value="{url}" />
    <Property Id="INSTALLDRIVER" Value="{'1' if with_driver else '0'}" />
    <Property Id="ENABLETESTSIGNING" Value="0" />
    <Property Id="ARPNOMODIFY" Value="1" />
    <Feature Id="Main" Title="ForensicAgent" Level="1">
      <ComponentGroupRef Id="ProductComponents" />
{driver_ref}    </Feature>
    <CustomAction Id="RunSetup" FileKey="SetupExe" ExeCommand="/S /URL=[SERVERURL] /DRIVER=[INSTALLDRIVER] /TESTSIGNING=[ENABLETESTSIGNING]"
                  Execute="deferred" Impersonate="no" Return="check" />
    <CustomAction Id="RunUninstall" FileKey="SetupExe" ExeCommand="/U"
                  Execute="deferred" Impersonate="no" Return="ignore" />
    <InstallExecuteSequence>
      <Custom Action="RunUninstall" Before="RemoveFiles">REMOVE~="ALL"</Custom>
      <Custom Action="RunSetup" After="InstallFiles">NOT REMOVE</Custom>
    </InstallExecuteSequence>
  </Product>
  <Fragment>
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="CommonAppDataFolder">
        <Directory Id="FADIR" Name="ForensicAgent">
          <Directory Id="INSTALLDIR" Name="pkg">
{driver_dir}          </Directory>
        </Directory>
      </Directory>
    </Directory>
  </Fragment>
  <Fragment>
    <ComponentGroup Id="ProductComponents" Directory="INSTALLDIR">
      <Component Id="CmpSetup" Guid="*"><File Id="SetupExe" Source="ForensicAgent-Setup.exe" KeyPath="yes" /></Component>
      <Component Id="CmpAgent" Guid="*"><File Id="AgentExe" Source="forensic-agent.exe" KeyPath="yes" /></Component>
      <Component Id="CmpCfg" Guid="*"><File Id="AgentJson" Source="agent.json" KeyPath="yes" /></Component>
    </ComponentGroup>
{driver_cmp}  </Fragment>
</Wix>
"""


def build_msi(*, setup_exe: Path, agent_exe: Path, agent_json_text: str,
              server_url: str, version: str, out_msi: Path) -> Optional[Path]:
    wix = wix_dir()
    if not wix or not setup_exe.is_file() or not agent_exe.is_file():
        return None
    with tempfile.TemporaryDirectory(prefix="fa_msi_") as td:
        work = Path(td)
        shutil.copy2(setup_exe, work / "ForensicAgent-Setup.exe")
        shutil.copy2(agent_exe, work / "forensic-agent.exe")
        (work / "agent.json").write_text(agent_json_text, encoding="utf-8")
        drv = driver_files()
        for p in drv:
            shutil.copy2(p, work / p.name)
        sm = sysmon_files()
        if sm:
            (work / "sysmon").mkdir(exist_ok=True)
            for p in sm:
                shutil.copy2(p, work / "sysmon" / p.name)
        (work / "ForensicAgent.wxs").write_text(
            _wxs(_msi_version(version), server_url, bool(drv), sm), encoding="utf-8")
        cp = subprocess.run([str(wix / "candle.exe"), "-nologo", "-fips", "ForensicAgent.wxs"],
                            cwd=str(work), capture_output=True, text=True, timeout=120)
        if cp.returncode != 0:
            raise RuntimeError("candle 失败: " + (cp.stdout + cp.stderr)[-800:])
        cp = subprocess.run([str(wix / "light.exe"), "-nologo", "-sval", "ForensicAgent.wixobj",
                             "-o", "ForensicAgent.msi"],
                            cwd=str(work), capture_output=True, text=True, timeout=180)
        if cp.returncode != 0 or not (work / "ForensicAgent.msi").is_file():
            raise RuntimeError("light 失败: " + (cp.stdout + cp.stderr)[-800:])
        out_msi.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(work / "ForensicAgent.msi", out_msi)
    return out_msi
