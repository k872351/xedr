import inspect
import unittest

from backend import agent_install_scripts, agent_linux_package


class InstallIdentityGuardTests(unittest.TestCase):
    def test_batch_refuses_existing_configuration_before_copy(self):
        script = agent_install_scripts.install_bat()
        guard = script.index('if exist "%DEST%\\agent.json" (')
        copy = script.index('copy /y "%~dp0agent.json"')
        self.assertLess(guard, copy)
        self.assertIn('exit /b 1', script[guard:copy])

    def test_gui_checks_existing_config_before_copy(self):
        script = agent_install_scripts.install_gui_ps1()
        self.assertIn('Existing configuration requires explicit migration', script)
        self.assertIn('if (Test-Path $existing) { Save-AgentJson $url }', script)
        self.assertNotIn('Copy-Item $CfgSrc (Join-Path $Dest', script)
        method = script[script.index('function Install-AgentCore'):]
        self.assertLess(method.index('Save-AgentJson $url'), method.index('Copy-Item $ExeSrc'))

    def test_linux_preflight_is_before_service_interruption(self):
        source = inspect.getsource(agent_linux_package.build_linux_package)
        self.assertLess(source.index('explicit migration required'), source.index('systemctl stop forensic-agent.service'))
        self.assertIn('if [ ! -e "$DEST/agent.json" ]; then', source)
        snippet = source.split("<<'PYCFG'\n", 1)[1].split('\nPYCFG', 1)[0]
        compile(snippet, '<installer-preflight>', 'exec')
