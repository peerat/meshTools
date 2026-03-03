#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

import meshTalk
from meshtalk.storage import Storage
from meshtalk.utils import encode_history_text
from meshtalk.compression import MODE_BZ2, compress_text


class MeshTalkHistoryTests(unittest.TestCase):
    def test_parse_history_record_line_with_meta_token(self) -> None:
        text = "line1 | line2"
        encoded = encode_history_text(text)
        meta = {"delivery": 1.5, "status": "timeout", "incoming": False}
        token = meshTalk.encode_history_meta_token(meta)
        line = (
            "2026-02-08 12:00:00 | sent | 12345678 | a1b2c3d4 | "
            f"{encoded} | parts=1 | {token}"
        )

        parsed = meshTalk.parse_history_record_line(line)
        self.assertIsNotNone(parsed)
        ts, direction, peer_id, msg_id, decoded_text, meta_data = parsed  # type: ignore[misc]
        self.assertEqual(ts, "2026-02-08 12:00:00")
        self.assertEqual(direction, "sent")
        self.assertEqual(peer_id, "12345678")
        self.assertEqual(msg_id, "a1b2c3d4")
        self.assertEqual(decoded_text, text)
        self.assertEqual(meta_data, meta)

    def test_parse_history_record_line_legacy_plain_text(self) -> None:
        line = "2026-02-08 12:00:00 | recv | 12345678 | deadbeef | plain legacy row | extra"
        parsed = meshTalk.parse_history_record_line(line)
        self.assertIsNotNone(parsed)
        ts, direction, peer_id, msg_id, decoded_text, meta_data = parsed  # type: ignore[misc]
        self.assertEqual(ts, "2026-02-08 12:00:00")
        self.assertEqual(direction, "recv")
        self.assertEqual(peer_id, "12345678")
        self.assertEqual(msg_id, "deadbeef")
        self.assertEqual(decoded_text, "plain legacy row | extra")
        self.assertIsNone(meta_data)

    def test_parse_history_record_line_legacy_plain_text_with_pipe_preserved(self) -> None:
        line = "2026-02-08 12:00:00 | recv | 12345678 | deadbeef | part A | part B"
        parsed = meshTalk.parse_history_record_line(line)
        self.assertIsNotNone(parsed)
        _ts, _direction, _peer_id, _msg_id, decoded_text, _meta_data = parsed  # type: ignore[misc]
        self.assertEqual(decoded_text, "part A | part B")

    def test_parse_history_record_line_rejects_broken_b64(self) -> None:
        line = "2026-02-08 12:00:00 | recv | 12345678 | deadbeef | b64:not_base64!"
        self.assertIsNone(meshTalk.parse_history_record_line(line))

    def test_effective_payload_cmp_label_compact_prefers_mc_generic_over_legacy_deflate(self) -> None:
        label = meshTalk.effective_payload_cmp_label(
            payload_cmp="deflate",
            compact_wire=True,
            compression_flag=1,
            legacy_codec="deflate",
            parts={},
            chunk_b64=None,
        )
        self.assertEqual(label, "mc")

    def test_effective_payload_cmp_label_compact_detects_mode_from_part1(self) -> None:
        blob = compress_text("тест сжатия", mode=MODE_BZ2, preserve_case=True)
        part1_b64 = meshTalk.b64e(blob[: min(len(blob), 64)])
        label = meshTalk.effective_payload_cmp_label(
            payload_cmp="deflate",
            compact_wire=True,
            compression_flag=1,
            legacy_codec="deflate",
            parts={"1": part1_b64},
            chunk_b64=None,
        )
        self.assertEqual(label, "mc_bz2")

    def test_storage_purge_history_peer_uses_lock_and_norm_fn(self) -> None:
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            cfg = os.path.join(d, "config.json")
            state = os.path.join(d, "state.json")
            history = os.path.join(d, "history.log")
            incoming = os.path.join(d, "incoming.json")
            runtime = os.path.join(d, "runtime.log")
            keydir = os.path.join(d, "keyRings")
            s = Storage(cfg, state, history, incoming, runtime, keydir)

            # Keep one malformed line, one line for our peer, and one for another peer.
            lines = [
                "broken line without separators\n",
                "2026-02-10 12:00:00 | sent | 12345678 | a | b64:AA==\n",
                "2026-02-10 12:00:01 | recv | deadbeef | b | b64:AA==\n",
            ]
            with open(history, "w", encoding="utf-8") as f:
                f.writelines(lines)

            s.purge_history_peer("!12345678", peer_norm_fn=lambda x: str(x).strip().lstrip("!"))

            with open(history, "r", encoding="utf-8") as f:
                kept = f.read().splitlines()
            self.assertIn("broken line without separators", kept)
            self.assertNotIn("2026-02-10 12:00:00 | sent | 12345678 | a | b64:AA==", kept)
            self.assertIn("2026-02-10 12:00:01 | recv | deadbeef | b | b64:AA==", kept)

    def test_storage_rewrite_history_peer_field_renames_group_exactly(self) -> None:
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            cfg = os.path.join(d, "config.json")
            state = os.path.join(d, "state.json")
            history = os.path.join(d, "history.log")
            incoming = os.path.join(d, "incoming.json")
            runtime = os.path.join(d, "runtime.log")
            keydir = os.path.join(d, "keyRings")
            s = Storage(cfg, state, history, incoming, runtime, keydir)

            old_id = "group:old"
            new_id = "group:new"
            encoded = encode_history_text("hi")
            lines = [
                f"2026-02-10 12:00:00 | sent | {old_id} | a | {encoded}\n",
                f"2026-02-10 12:00:01 | recv | {new_id} | b | {encoded}\n",
            ]
            with open(history, "w", encoding="utf-8") as f:
                f.writelines(lines)

            s.rewrite_history_peer_field(old_id, new_id)
            with open(history, "r", encoding="utf-8") as f:
                out = f.read()
            self.assertIn(f"sent | {new_id} | a", out)
            self.assertNotIn(f"sent | {old_id} | a", out)
            # Unrelated line stays.
            self.assertIn(f"recv | {new_id} | b", out)


if __name__ == "__main__":
    unittest.main()
