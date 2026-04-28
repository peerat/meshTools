import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import meshLogger


ROOT = Path(__file__).resolve().parents[1]
MESH_LOGGER = ROOT / "meshLogger.py"


class MeshLoggerCliTests(unittest.TestCase):
    def test_version_has_no_runtime_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            result = subprocess.run(
                ["python3", str(MESH_LOGGER), "--version"],
                cwd=tmp_dir,
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertIn("meshLogger.py v", result.stdout)
            self.assertEqual(list(Path(tmp_dir).iterdir()), [])

    def test_auto_port_mode_does_not_force_port_flag(self) -> None:
        self.assertEqual(meshLogger._port_cli_args(None), [])
        self.assertEqual(meshLogger._port_display(None), "auto")

        def _fake_isfile(path: str) -> bool:
            return path in {"/tmp/helper.py", "/usr/bin/python3"}

        with mock.patch.object(meshLogger, "_meshtastic_helper_script_path", return_value="/tmp/helper.py"):
            with mock.patch.object(meshLogger, "_resolve_meshtastic_python", return_value="/usr/bin/python3"):
                with mock.patch.object(meshLogger.os.path, "isfile", side_effect=_fake_isfile):
                    cmd = meshLogger._build_listen_command(None, 45)

        self.assertEqual(cmd, ["/usr/bin/python3", "/tmp/helper.py", "--timeout", "45"])

    def test_fetch_nodes_json_scans_ports_and_remembers_working_one(self) -> None:
        side_effects = [
            (0, "Connected to radio\nusage: meshtastic ...", ""),
            (0, "Connected to radio\nusage: meshtastic ...", ""),
            (0, "Connected to radio\nNodes in mesh: none", ""),
            (0, '[{"user": {"id": "!12345678", "longName": "Alpha", "shortName": "A"}}]', ""),
        ]

        with mock.patch.object(meshLogger, "ACTIVE_PORT_HINT", None):
            with mock.patch.object(meshLogger, "_list_serial_ports", return_value=["COM5"]):
                with mock.patch.object(meshLogger, "run_cmd", side_effect=side_effects) as run_cmd:
                    nodes = meshLogger.fetch_nodes_json(None, timeout=10)
                    active_hint = meshLogger.ACTIVE_PORT_HINT

        self.assertIsNotNone(nodes)
        self.assertEqual(active_hint, "COM5")
        self.assertEqual(run_cmd.call_count, 4)
        called_cmd = run_cmd.call_args_list[-1].args[0]
        self.assertIn("--port", called_cmd)
        self.assertIn("COM5", called_cmd)

    def test_build_listen_command_uses_cli_in_frozen_windows_mode(self) -> None:
        with mock.patch.object(meshLogger.os, "name", "nt"):
            with mock.patch.object(meshLogger.sys, "frozen", True, create=True):
                with mock.patch.object(meshLogger, "_meshtastic_cmd_bases", return_value=[["py", "-3", "-m", "meshtastic"]]):
                    cmd = meshLogger._build_listen_command("COM5", 45)
        self.assertEqual(cmd, ["py", "-3", "-m", "meshtastic", "--port", "COM5", "--listen"])

    def test_run_meshtastic_cli_falls_back_from_missing_module_runner_to_plain_cli(self) -> None:
        side_effects = [
            (1, "", "No module named meshtastic"),
            (0, "Connected to radio\n{}", ""),
        ]
        with mock.patch.object(meshLogger, "_meshtastic_cmd_bases", return_value=[["py", "-3", "-m", "meshtastic"], ["meshtastic"]]):
            with mock.patch.object(meshLogger, "run_cmd", side_effect=side_effects) as run_cmd:
                rc, so, se = meshLogger._run_meshtastic_cli(["--info"], timeout=10)

        self.assertEqual((rc, so, se), (0, "Connected to radio\n{}", ""))
        self.assertEqual(run_cmd.call_count, 2)
        self.assertEqual(run_cmd.call_args_list[0].args[0], ["py", "-3", "-m", "meshtastic", "--info"])
        self.assertEqual(run_cmd.call_args_list[1].args[0], ["meshtastic", "--info"])

    def test_frozen_windows_cmd_bases_do_not_use_py_launcher(self) -> None:
        with mock.patch.object(meshLogger.os, "name", "nt"):
            with mock.patch.object(meshLogger.sys, "frozen", True, create=True):
                with mock.patch.dict(meshLogger.os.environ, {}, clear=True):
                    with mock.patch.object(meshLogger.shutil, "which", return_value="C:\\Windows\\py.exe"):
                        bases = meshLogger._meshtastic_cmd_bases()

        self.assertEqual(bases, [["meshtastic"]])

    def test_connection_errors_are_retryable(self) -> None:
        self.assertTrue(meshLogger._is_retryable_connection_error("device not found using automatic port detection"))
        self.assertTrue(meshLogger._is_retryable_connection_error("device busy on port COM3"))
        self.assertTrue(meshLogger._is_retryable_connection_error("multiple serial ports were detected"))
        self.assertTrue(meshLogger._is_retryable_connection_error("meshtastic CLI was not found in PATH"))
        self.assertTrue(meshLogger._is_retryable_connection_error("cannot parse nodes block"))
        self.assertIn("Waiting for device", meshLogger._retry_status_message("device not found", None))
        self.assertIn("port busy", meshLogger._retry_status_message("device busy on port COM3", "COM3"))
        self.assertIn("--port", meshLogger._retry_status_message("multiple serial ports were detected", None))
        self.assertIn("meshtastic CLI", meshLogger._retry_status_message("meshtastic CLI was not found in PATH", None))
        self.assertIn("node list", meshLogger._retry_status_message("cannot parse nodes block", None))

    def test_detect_device_busy_matches_windows_permission_denied_port_error(self) -> None:
        text = "serial.serialutil.SerialException: could not open port 'COM5': PermissionError(13, 'Отказано в доступе.', None, 5)"
        self.assertTrue(meshLogger.detect_device_busy(text))

    def test_run_cmd_translates_missing_meshtastic_cli(self) -> None:
        with mock.patch.object(meshLogger, "_popen_new_process_group", side_effect=FileNotFoundError()):
            with self.assertRaises(RuntimeError) as ctx:
                meshLogger.run_cmd(["meshtastic", "--info"], timeout=5)
        self.assertIn("meshtastic CLI was not found in PATH", str(ctx.exception))

    def test_run_cmd_timeout_returns_drained_partial_output(self) -> None:
        class _FakeProc:
            def __init__(self) -> None:
                self.returncode = None
                self.killed = False

            def communicate(self, timeout=None):  # noqa: ANN001
                if self.killed:
                    self.returncode = 124
                    return ("Route traced towards destination:\n!11111111 --> !22222222 (3.5dB)\n", "")
                return ("", "")

            def poll(self):
                return self.returncode

        fake_proc = _FakeProc()

        def _fake_terminate(proc):  # noqa: ANN001
            proc.killed = True

        with mock.patch.object(meshLogger, "_popen_new_process_group", return_value=fake_proc):
            with mock.patch.object(meshLogger, "stop_listen", return_value=None):
                with mock.patch.object(meshLogger, "set_listen_suspended", return_value=None):
                    with mock.patch.object(meshLogger, "_terminate_process", side_effect=_fake_terminate):
                        with mock.patch.object(meshLogger.time, "sleep", return_value=None):
                            with mock.patch.object(meshLogger.time, "time", side_effect=[0.0, 31.0]):
                                rc, so, se = meshLogger.run_cmd(["meshtastic", "--traceroute", "!22222222"], timeout=30)

        self.assertEqual(rc, 124)
        self.assertIn("Route traced towards destination:", so)
        self.assertIn("[TIMEOUT]", se)

    def test_nodes_list_to_dict_normalizes_ids(self) -> None:
        nodes = meshLogger._nodes_list_to_dict(
            [
                {"user": {"id": "!ABCDEF12", "longName": "Alpha", "shortName": "A"}, "num": 123},
                {"id": "!12345678", "user": {"longName": "Bravo", "shortName": "B"}, "num": 456},
            ]
        )
        self.assertIn("!abcdef12", nodes)
        self.assertIn("!12345678", nodes)
        self.assertEqual(nodes["!abcdef12"]["user"]["id"], "!abcdef12")
        self.assertEqual(nodes["!12345678"]["id"], "!12345678")

    def test_schedule_active_nodes_skips_transit_and_round_robins_direct_nodes_in_tune(self) -> None:
        active = [
            meshLogger.NodeRec("!direct2", "Direct Two", "D2", 300, 1),
            meshLogger.NodeRec("!far", "Far", "F", 300, 4),
            meshLogger.NodeRec("!relay", "Relay", "R", 300, 2),
            meshLogger.NodeRec("!direct1", "Direct One", "D1", 300, 1),
        ]

        scheduled = meshLogger._schedule_active_nodes(
            active,
            tune_mode=True,
            direct_ids={"!direct1", "!direct2"},
            transit_ids={"!relay"},
            sample_counts={"!direct1": 5, "!direct2": 1},
            poll_order={"!direct1": 20, "!direct2": 10},
        )

        self.assertEqual([node.node_id for node in scheduled], ["!direct2", "!direct1", "!far"])

    def test_schedule_active_nodes_prefers_far_nodes_and_skips_transit_in_normal_mode(self) -> None:
        active = [
            meshLogger.NodeRec("!near", "Near", "N", 300, 1),
            meshLogger.NodeRec("!mid", "Mid", "M", 300, 2),
            meshLogger.NodeRec("!far", "Far", "F", 300, 4),
        ]

        scheduled = meshLogger._schedule_active_nodes(
            active,
            tune_mode=False,
            direct_ids=set(),
            transit_ids={"!mid"},
        )

        self.assertEqual([node.node_id for node in scheduled], ["!far", "!near"])

    def test_poll_members_signature_depends_only_on_member_ids_not_order(self) -> None:
        a = [
            meshLogger.NodeRec("!b", "B", "B", 300, 1),
            meshLogger.NodeRec("!a", "A", "A", 300, 2),
        ]
        b = [
            meshLogger.NodeRec("!a", "A", "A", 300, 2),
            meshLogger.NodeRec("!b", "B", "B", 300, 1),
        ]
        c = [
            meshLogger.NodeRec("!a", "A", "A", 300, 2),
            meshLogger.NodeRec("!c", "C", "C", 300, 1),
        ]

        self.assertEqual(meshLogger._poll_members_signature(a), meshLogger._poll_members_signature(b))
        self.assertNotEqual(meshLogger._poll_members_signature(a), meshLogger._poll_members_signature(c))

    def test_parse_routes_from_meshtastic_output_supports_route_traced_variant(self) -> None:
        raw = """
[13:07:47]INFO  | ??:??:?? 696 [Router] Route traced:
[13:07:47]0x7d085940 --> 0xb2a72678 (7.00dB)
[13:07:47](6.25dB) 0x7d085940 <-- 0xb2a72678
"""
        towards, back = meshLogger.parse_routes_from_meshtastic_output(raw)
        self.assertEqual(towards, "!7d085940 --> !b2a72678 (7.00dB)")
        self.assertEqual(back, "!b2a72678 --> !7d085940 (6.25dB)")

    def test_summarize_traceroute_output_ignores_timeout_marker(self) -> None:
        raw = "\n[TIMEOUT]\nConnected to radio\nNo response from node\n"
        self.assertEqual(
            meshLogger._summarize_traceroute_output(raw),
            "Connected to radio | No response from node",
        )


if __name__ == "__main__":
    unittest.main()
