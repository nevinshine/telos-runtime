import importlib.util
import pathlib
import tempfile
import unittest
import unittest.mock
import os


ROOT = pathlib.Path(__file__).resolve().parents[1]
CLI_PATH = ROOT / "telos_cli.py"


def load_telos_cli():
    spec = importlib.util.spec_from_file_location("telos_cli", CLI_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@unittest.skipIf(os.name == "nt" or not hasattr(os, "symlink"), "Unix-only symlink behavior")
class PidFileHardeningTest(unittest.TestCase):
    def test_secure_write_and_reject_symlink(self):
        telos_cli = load_telos_cli()
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            pid_file = td / "telos_daemon.pid"

            # Legitimate writer should be accepted (patch os.kill to avoid ProcessLookupError for dummy PID)
            telos_cli.secure_write_pid(pid_file, 424242)
            with unittest.mock.patch('os.kill', return_value=None):
                self.assertEqual(telos_cli.pid_alive(pid_file), 424242)

            # Now create a forged pid target and replace with a symlink
            forged = td / "forged.pid"
            forged.write_text("12345\n")
            pid_file.unlink()
            os.symlink(str(forged), str(pid_file))

            # Symlink should be rejected by secure reader
            self.assertIsNone(telos_cli.pid_alive(pid_file))


if __name__ == "__main__":
    unittest.main()
