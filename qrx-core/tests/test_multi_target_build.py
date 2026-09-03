import json
import platform
import subprocess
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
SCRIPT=ROOT/"scripts"/"build-all-targets.sh"

class MultiTargetBuildTests(unittest.TestCase):
    def test_all_supported_plans_are_complete_and_ordered(self):
        targets={
            "linux-x64":"x86_64-unknown-linux-gnu",
            "linux-arm64":"aarch64-unknown-linux-gnu",
            "macos-x64":"x86_64-apple-darwin",
            "macos-arm64":"aarch64-apple-darwin",
            "windows-x64":"x86_64-pc-windows-msvc",
        }
        for target,triple in targets.items():
            run=subprocess.run(["bash",str(SCRIPT),"--target",target,"--plan"],text=True,capture_output=True)
            self.assertEqual(run.returncode,0,run.stderr);self.assertIn(triple,run.stdout)
            positions=[run.stdout.index(f"  {n}.") for n in range(1,8)]
            self.assertEqual(positions,sorted(positions))

    def test_tauri_is_built_after_sidecars(self):
        source=SCRIPT.read_text()
        self.assertLess(source.index('Installing exact target-suffixed Tauri sidecars'),source.index('Building Tauri desktop wallet after its Core dependencies'))
        for name in ("qrx","qrx-cli","qrxd","qrx-btc-wallet-service"):
            self.assertIn(name,source)

    def test_ci_matrix_has_five_native_targets(self):
        workflow=(ROOT/".github"/"workflows"/"build-all-targets.yml").read_text()
        for target in ("linux-x64","linux-arm64","macos-x64","macos-arm64","windows-x64"):
            self.assertEqual(workflow.count(f"target: {target}"),1)
        self.assertIn("max-parallel: 5",workflow)

    def test_all_plan_dispatches_every_target_without_network(self):
        run=subprocess.run(["bash",str(SCRIPT),"--all","--plan"],text=True,capture_output=True)
        self.assertEqual(run.returncode,0,run.stderr)
        for target in ("linux-x64","linux-arm64","macos-x64","macos-arm64","windows-x64"):
            self.assertIn(f"QRX release plan: {target}",run.stdout)

    def test_host_target_detects_current_linux_architecture(self):
        run=subprocess.run(["bash",str(SCRIPT),"--target","host","--plan"],text=True,capture_output=True)
        self.assertEqual(run.returncode,0,run.stderr)
        machine=platform.machine().lower()
        expected="linux-arm64" if machine in {"aarch64","arm64"} else "linux-x64"
        self.assertIn(f"Auto-detected host target: {expected}",run.stdout)

    def test_package_metadata_is_valid(self):
        json.loads((ROOT/"GUIWALLET"/"package.json").read_text())

if __name__=="__main__":unittest.main()
