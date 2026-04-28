import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import nodeDbUpdater


class NodeDbUpdaterTests(unittest.TestCase):
    def test_run_cmd_returns_timeout_tuple(self) -> None:
        timeout = subprocess.TimeoutExpired(cmd=["meshtastic"], timeout=5, output="partial", stderr="too slow")
        with mock.patch("nodeDbUpdater.subprocess.run", side_effect=timeout):
            returncode, stdout, stderr = nodeDbUpdater.run_cmd(["meshtastic"], timeout=5)

        self.assertEqual(returncode, 124)
        self.assertEqual(stdout, "partial")
        self.assertEqual(stderr, "too slow")

    def test_main_returns_error_on_nodes_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "nodeDb.txt"
            with mock.patch("nodeDbUpdater.run_cmd", return_value=(124, "", "[TIMEOUT]")), mock.patch.object(sys, "argv", ["nodeDbUpdater.py", "--db", str(db_path), "--port", "/dev/null"]):
                rc = nodeDbUpdater.main()

            self.assertEqual(rc, 2)
            self.assertFalse(db_path.exists())

    def test_main_accepts_dict_json_and_preserves_zero_values(self) -> None:
        nodes_payload = {
            "nodes": {
                "!11111111": {
                    "longName": "Alpha",
                    "shortName": "A",
                    "hwModel": "T-ECHO",
                    "batteryLevel": 0,
                    "snr": 0,
                    "lastHeard": 0,
                    "since": 0,
                    "latitude": 0,
                    "longitude": 0,
                    "altitude": 0,
                }
            }
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "nodeDb.txt"
            with mock.patch(
                "nodeDbUpdater.run_cmd",
                side_effect=[
                    (0, json.dumps(nodes_payload), ""),
                    (0, "owner: tester\n", ""),
                ],
            ), mock.patch.object(
                sys,
                "argv",
                ["nodeDbUpdater.py", "--db", str(db_path), "--port", "/dev/null"],
            ):
                rc = nodeDbUpdater.main()

            db = json.loads(db_path.read_text(encoding="utf-8"))

        self.assertEqual(rc, 0)
        current = db["nodes"]["!11111111"]["current"]
        self.assertEqual(current["user"], "Alpha")
        self.assertEqual(current["aka"], "A")
        self.assertEqual(current["hardware"], "T-ECHO")
        self.assertEqual(current["battery"]["percent"], 0.0)
        self.assertEqual(current["snr_db"], 0.0)
        self.assertEqual(current["position"]["lat"], 0.0)
        self.assertEqual(current["position"]["lon"], 0.0)
        self.assertEqual(current["position"]["alt_m"], 0.0)
        self.assertEqual(current["last_heard"], 0)
        self.assertEqual(current["since"], 0)


if __name__ == "__main__":
    unittest.main()
