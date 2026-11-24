import io
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.verify_release import read_pe_architecture
from backend.agent_release import windows_agent_path
from backend.agent_package_builder import agent_binary_path
from backend.agent_linux_package import _SUPPORTED_ARCHES as LINUX_AGENT_ARCHES
from backend import agent_release
from backend import config


class ReleaseArchitectureTests(unittest.TestCase):
    def test_windows_machine_types(self):
        for machine, arch in [(0x014C, "386"), (0x8664, "amd64"), (0xAA64, "arm64")]:
            header = bytearray(64)
            header[:2] = b"MZ"
            struct.pack_into("<I", header, 60, 64)
            binary = bytes(header) + b"PE\x00\x00" + struct.pack("<H", machine)
            self.assertEqual(read_pe_architecture(io.BytesIO(binary)), arch)

    def test_invalid_header(self):
        with self.assertRaises(ValueError):
            read_pe_architecture(io.BytesIO(b"bad file"))

    def test_windows_release_targets_have_isolated_paths(self):
        x64 = windows_agent_path("amd64")
        x86 = windows_agent_path("386")
        arm64 = windows_agent_path("arm64")
        self.assertNotEqual(x64, x86)
        self.assertNotEqual(x64, arm64)
        self.assertEqual(x86.parts[-3:], ("windows", "386", "forensic-agent.exe"))
        self.assertEqual(arm64.parts[-3:], ("windows", "arm64", "forensic-agent.exe"))
        with self.assertRaises(ValueError):
            windows_agent_path("loong64")

    def test_windows_package_resolves_the_selected_architecture(self):
        root = Path("D:/test-root")
        variant = root / "agent" / "releases" / "windows" / "arm64" / "forensic-agent.exe"
        with (
            patch.object(config, "ROOT", root),
            patch.object(Path, "is_file", return_value=True),
            patch.object(Path, "stat", return_value=SimpleNamespace(st_size=100_001)),
        ):
            self.assertEqual(agent_binary_path("arm64"), variant)
            self.assertNotEqual(agent_binary_path("386"), variant)

    def test_linux_release_architectures_include_riscv_and_loongarch(self):
        self.assertEqual(LINUX_AGENT_ARCHES, {"amd64", "arm64", "loong64", "riscv64"})

    def test_background_build_uses_selected_arch_and_records_result(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / "scripts" / "build_agent.py").write_text("# build entry", encoding="utf-8")
            expected = root / "agent" / "forensic-agent.exe"
            completed = SimpleNamespace(returncode=0, stdout=b"built", stderr=b"")
            with (
                patch.object(config, "ROOT", root),
                patch.object(agent_release, "_find_go", return_value="go"),
                patch.object(agent_release.subprocess, "run", return_value=completed) as run,
                patch.object(agent_release, "release_status", return_value={"status": "latest"}),
                patch("backend.agent_protocol.clear_install_package_cache", return_value=0),
            ):
                result = agent_release.run_build(goarch="amd64")
            self.assertTrue(result["ok"], result)
            self.assertEqual(run.call_args.args[0][run.call_args.args[0].index("--goarch") + 1], "amd64")
            self.assertEqual(run.call_args.args[0][run.call_args.args[0].index("--out") + 1], str(expected))
            self.assertEqual(agent_release._build_state["last"]["goarch"], "amd64")

    def test_background_build_rejects_invalid_architecture(self):
        result = agent_release.run_build(goarch="loong64")
        self.assertFalse(result["ok"])
        self.assertIn("Unsupported Windows architecture", result["error"])
