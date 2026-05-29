import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CLI_PATH = ROOT / "telos_cli.py"


def load_telos_cli():
    spec = importlib.util.spec_from_file_location("telos_cli", CLI_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class PidFilePathTest(unittest.TestCase):
    def test_pid_files_live_under_var_run(self):
        telos_cli = load_telos_cli()

        self.assertEqual(telos_cli.DAEMON_PID_FILE.as_posix(), "/var/run/telos_daemon.pid")
        self.assertEqual(telos_cli.CORTEX_PID_FILE.as_posix(), "/var/run/telos_cortex.pid")
        self.assertEqual(telos_cli.TUI_PID_FILE.as_posix(), "/var/run/telos_tui.pid")


if __name__ == "__main__":
    unittest.main()