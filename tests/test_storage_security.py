import os
import tempfile
import unittest


class TestStorageSecurity(unittest.TestCase):
    def tearDown(self):
        from meshtalk.utils import set_history_encryption_key

        set_history_encryption_key(None)

    def test_append_history_requires_storage_key(self):
        from meshtalk.storage import Storage

        with tempfile.TemporaryDirectory() as td:
            history_file = os.path.join(td, "history.log")
            storage = Storage(
                config_file=os.path.join(td, "config.json"),
                state_file=os.path.join(td, "state.json"),
                history_file=history_file,
                incoming_file=os.path.join(td, "incoming.json"),
                runtime_log_file=os.path.join(td, "runtime.log"),
                keydir="",  # no key path -> key cannot be created
            )
            storage.append_history("sent", "peer01", "m1", "secret text")
            self.assertFalse(os.path.exists(history_file))

    def test_state_and_incoming_are_encrypted_when_key_exists(self):
        from meshtalk.storage import Storage

        with tempfile.TemporaryDirectory() as td:
            keydir = os.path.join(td, "keyRings")
            storage = Storage(
                config_file=os.path.join(td, "config.json"),
                state_file=os.path.join(td, "state.json"),
                history_file=os.path.join(td, "history.log"),
                incoming_file=os.path.join(td, "incoming.json"),
                runtime_log_file=os.path.join(td, "runtime.log"),
                keydir=keydir,
            )
            storage.ensure_storage_key()
            storage.save_state(
                {
                    "peer01": {
                        "m1": {
                            "id": "m1",
                            "peer": "peer01",
                            "text": "sensitive",
                            "chunk_text": "chunk",
                            "chunk_b64": "Y2h1bms=",
                        }
                    }
                }
            )
            storage.save_incoming_state(
                {
                    "peer01:g1": {
                        "peer": "peer01",
                        "group_id": "g1",
                        "total": 1,
                        "parts": {"1": "payload"},
                    }
                }
            )

            with open(os.path.join(td, "state.json"), "r", encoding="utf-8") as f:
                state_raw = f.read()
            with open(os.path.join(td, "incoming.json"), "r", encoding="utf-8") as f:
                incoming_raw = f.read()
            self.assertIn("enc1:", state_raw)
            self.assertIn("enc1:", incoming_raw)
            self.assertNotIn("sensitive", state_raw)
            self.assertNotIn('"1": "payload"', incoming_raw)


if __name__ == "__main__":
    unittest.main()
