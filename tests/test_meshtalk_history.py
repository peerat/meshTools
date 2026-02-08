#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

import meshTalk
from meshtalk_utils import encode_history_text
from message_text_compression import MODE_BZ2, compress_text


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


if __name__ == "__main__":
    unittest.main()
