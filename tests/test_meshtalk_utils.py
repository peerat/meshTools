#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import time
import hashlib
import struct
import unittest

from meshtalk_utils import (
    format_meta_text,
    snapshot_runtime_state,
    maybe_compress_for_encrypt,
    maybe_decompress_after_decrypt,
    compress_for_encrypt_with_method,
    compression_method_from_payload,
    COMPRESS_TAG,
    COMPRESS_TAG_BZ2,
    COMPRESS_TAG_LZMA,
    COMPRESS_METHOD_NONE,
    COMPRESS_METHOD_ZLIB,
    COMPRESS_METHOD_BZ2,
    COMPRESS_METHOD_LZMA,
    compress_message_blob_best,
    decompress_message_blob,
    try_decompress_message_blob,
    message_codec_to_id,
    message_codec_from_id,
    build_legacy_chunks,
    build_legacy_wire_payload,
    build_compact_wire_payload,
    parse_legacy_wire_payload,
    parse_compact_meta,
    parse_key_exchange_frame,
    validate_key_frame_source,
    key_frame_receive_policy,
    merge_compact_compression,
    looks_like_mc_block,
    encode_history_text,
    decode_history_text,
    parse_history_line,
    assemble_compact_parts,
    normalize_log_text_line,
)
from message_text_compression import compress_text, MODE_BYTE_DICT


class _State:
    def __init__(self, rtt_avg: float, rtt_count: int) -> None:
        self.rtt_avg = rtt_avg
        self.rtt_count = rtt_count


class _FlakyItemsDict(dict):
    def __init__(self, fail_times: int, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._fail_times = int(fail_times)

    def items(self):
        if self._fail_times > 0:
            self._fail_times -= 1
            raise RuntimeError("dictionary changed size during iteration")
        return super().items()


class _AlwaysFailDict(dict):
    def items(self):
        raise RuntimeError("dictionary changed size during iteration")


class MeshTalkUtilsTests(unittest.TestCase):
    def test_normalize_log_text_line_collapses_duplicate_timestamp(self) -> None:
        line, body = normalize_log_text_line(
            "2026-02-08 12:00:00 2026-02-08 12:00:00 KEY: exchange complete"
        )
        self.assertEqual(line, "2026-02-08 12:00:00 KEY: exchange complete")
        self.assertEqual(body, "KEY: exchange complete")

    def test_normalize_log_text_line_adds_timestamp_when_missing(self) -> None:
        line, body = normalize_log_text_line("SEND: abc attempt=1", fallback_ts="2026-02-08 12:00:01")
        self.assertEqual(line, "2026-02-08 12:00:01 SEND: abc attempt=1")
        self.assertEqual(body, "SEND: abc attempt=1")

    def test_compress_roundtrip_when_beneficial(self) -> None:
        data = (b"A" * 1024) + (b"B" * 512)
        packed = maybe_compress_for_encrypt(data)
        self.assertTrue(
            packed.startswith(COMPRESS_TAG)
            or packed.startswith(COMPRESS_TAG_BZ2)
            or packed.startswith(COMPRESS_TAG_LZMA)
        )
        self.assertLess(len(packed), len(data))
        unpacked = maybe_decompress_after_decrypt(packed)
        self.assertEqual(unpacked, data)

    def test_compress_keeps_original_when_not_beneficial(self) -> None:
        data = b"ACK"
        packed = maybe_compress_for_encrypt(data)
        self.assertEqual(packed, data)
        unpacked = maybe_decompress_after_decrypt(packed)
        self.assertEqual(unpacked, data)

    def test_compress_with_method_reports_codec(self) -> None:
        data = (b"A" * 1024) + (b"B" * 512)
        packed, method = compress_for_encrypt_with_method(data)
        self.assertIn(method, {COMPRESS_METHOD_ZLIB, COMPRESS_METHOD_BZ2, COMPRESS_METHOD_LZMA})
        self.assertEqual(compression_method_from_payload(packed), method)
        self.assertEqual(maybe_decompress_after_decrypt(packed), data)

    def test_compression_method_from_payload_for_raw_data(self) -> None:
        self.assertEqual(compression_method_from_payload(b"ACK"), COMPRESS_METHOD_NONE)

    def test_message_blob_compress_roundtrip(self) -> None:
        data = (b"meshTalk payload " * 200) + b"end"
        packed, codec = compress_message_blob_best(data)
        out = decompress_message_blob(packed, codec)
        self.assertEqual(out, data)

    def test_try_decompress_message_blob_strict(self) -> None:
        data = (b"meshTalk payload " * 120) + b"end"
        packed, codec = compress_message_blob_best(data)
        out, ok = try_decompress_message_blob(packed, codec)
        self.assertTrue(ok)
        self.assertEqual(out, data)
        broken, ok_broken = try_decompress_message_blob(b"broken", "deflate")
        self.assertFalse(ok_broken)
        self.assertEqual(broken, b"")

    def test_message_codec_id_mapping(self) -> None:
        for codec in ("none", "deflate", "zlib", "bz2", "lzma"):
            cid = message_codec_to_id(codec)
            self.assertEqual(message_codec_from_id(cid), codec)
        self.assertEqual(message_codec_from_id(255), "none")

    def test_decompress_fallback_on_invalid_payload(self) -> None:
        broken = COMPRESS_TAG + b"not-zlib-data"
        out = maybe_decompress_after_decrypt(broken)
        self.assertEqual(out, broken)

    def test_decompress_supports_all_known_tags(self) -> None:
        data = (b"meshTalk " * 120) + b"payload"
        import bz2
        import lzma
        import zlib

        z = COMPRESS_TAG + zlib.compress(data, level=9)
        b = COMPRESS_TAG_BZ2 + bz2.compress(data, compresslevel=9)
        x = COMPRESS_TAG_LZMA + lzma.compress(data, preset=9)

        self.assertEqual(maybe_decompress_after_decrypt(z), data)
        self.assertEqual(maybe_decompress_after_decrypt(b), data)
        self.assertEqual(maybe_decompress_after_decrypt(x), data)

    def test_format_meta_incoming_uses_received_timestamp(self) -> None:
        fixed_ts = 1700000000.0
        sent_ts = fixed_ts - 6.0
        expected_sent_hhmm = time.strftime("%H:%M", time.localtime(sent_ts))
        expected_hhmm = time.strftime("%H:%M", time.localtime(fixed_ts))
        meta = format_meta_text(
            "ru",
            delivery=6.0,
            attempts=1.0,
            forward_hops=0.0,
            ack_hops=None,
            packets=(1, 1),
            incoming=True,
            done=True,
            received_at_ts=fixed_ts,
            now_ts=fixed_ts + 7200.0,
        )
        self.assertIn(f"отправлено в {expected_sent_hhmm}", meta)
        self.assertIn(f"получено в {expected_hhmm}", meta)
        self.assertIn("за 00:06", meta)

    def test_format_meta_multipart_has_no_avg_markers(self) -> None:
        ru = format_meta_text(
            "ru",
            delivery=78.0,
            attempts=2.5,
            forward_hops=3.0,
            ack_hops=1.5,
            packets=(3, 5),
            delivered_at_ts=1700000000.0,
        )
        en = format_meta_text(
            "en",
            delivery=78.0,
            attempts=2.5,
            forward_hops=3.0,
            ack_hops=1.5,
            packets=(3, 5),
            delivered_at_ts=1700000000.0,
        )
        self.assertNotIn("ср", ru)
        self.assertNotIn("avg", en.lower())
        self.assertIn("части 3/5", ru)
        self.assertIn("parts 3/5", en)

    def test_format_meta_single_packet_hides_parts(self) -> None:
        ru = format_meta_text(
            "ru",
            delivery=6.0,
            attempts=1.0,
            forward_hops=0.0,
            ack_hops=0.0,
            packets=(1, 1),
            delivered_at_ts=1700000000.0,
        )
        en = format_meta_text(
            "en",
            delivery=6.0,
            attempts=1.0,
            forward_hops=0.0,
            ack_hops=0.0,
            packets=(1, 1),
            delivered_at_ts=1700000000.0,
        )
        self.assertNotIn("части", ru)
        self.assertNotIn("parts", en.lower())

    def test_format_meta_pending_single_packet_has_placeholder_status(self) -> None:
        ru = format_meta_text(
            "ru",
            delivery=None,
            attempts=0.0,
            forward_hops=None,
            ack_hops=None,
            packets=(0, 1),
            incoming=False,
            done=False,
        )
        en = format_meta_text(
            "en",
            delivery=None,
            attempts=0.0,
            forward_hops=None,
            ack_hops=None,
            packets=(0, 1),
            incoming=False,
            done=False,
        )
        self.assertEqual(ru, "в процессе")
        self.assertEqual(en, "in progress")

    def test_format_meta_decode_error_status_en(self) -> None:
        en = format_meta_text(
            "en",
            delivery=3.0,
            attempts=None,
            forward_hops=None,
            ack_hops=None,
            packets=(1, 1),
            status="decode_error",
        )
        self.assertIn("failed (decode error)", en)

    def test_format_meta_appends_compression_details_en(self) -> None:
        en = format_meta_text(
            "en",
            delivery=6.0,
            attempts=1.0,
            forward_hops=0.0,
            ack_hops=0.0,
            packets=(1, 1),
            delivered_at_ts=1700000000.0,
            compression_name="ZLIB",
            compression_eff_pct=37.4,
        )
        self.assertIn("compression ZLIB 37.4%", en)

    def test_format_meta_appends_compression_details_ru(self) -> None:
        ru = format_meta_text(
            "ru",
            delivery=6.0,
            attempts=1.0,
            forward_hops=0.0,
            ack_hops=0.0,
            packets=(1, 1),
            delivered_at_ts=1700000000.0,
            compression_name="BYTE_DICT",
            compression_eff_pct=42.0,
        )
        self.assertIn("сжатие BYTE_DICT 42%", ru)

    def test_format_meta_pending_single_packet_with_sent_timer(self) -> None:
        sent_at_ts = 1700000000.0
        sent_hhmm = time.strftime("%H:%M", time.localtime(sent_at_ts))
        ru = format_meta_text(
            "ru",
            delivery=None,
            attempts=0.0,
            forward_hops=None,
            ack_hops=None,
            packets=(0, 1),
            incoming=False,
            done=False,
            sent_at_ts=sent_at_ts,
            now_ts=sent_at_ts + 5.0,
        )
        en = format_meta_text(
            "en",
            delivery=None,
            attempts=0.0,
            forward_hops=None,
            ack_hops=None,
            packets=(0, 1),
            incoming=False,
            done=False,
            sent_at_ts=sent_at_ts,
            now_ts=sent_at_ts + 5.0,
        )
        self.assertEqual(ru, f"отправлено в {sent_hhmm} прошло 00:05")
        self.assertEqual(en, f"sent at {sent_hhmm} elapsed 00:05")

    def test_format_meta_incoming_progress_phrase_ru(self) -> None:
        started_ts = 1700000000.0
        started_hhmm = time.strftime("%H:%M", time.localtime(started_ts))
        ru = format_meta_text(
            "ru",
            delivery=None,
            attempts=1.0,
            forward_hops=3.0,
            ack_hops=None,
            packets=(1, 3),
            incoming=True,
            done=False,
            incoming_started_ts=started_ts,
            now_ts=started_ts + 15.0,
        )
        self.assertEqual(ru, f"в {started_hhmm} начали прием, прошло 00:15 частей 1/3 с 1 попытки, хопов 3")

    def test_format_meta_incoming_done_phrase_ru(self) -> None:
        sent_ts = 1700000000.0
        recv_ts = sent_ts + 78.0
        sent_hhmm = time.strftime("%H:%M", time.localtime(sent_ts))
        recv_hhmm = time.strftime("%H:%M", time.localtime(recv_ts))
        ru = format_meta_text(
            "ru",
            delivery=78.0,
            attempts=1.0,
            forward_hops=0.0,
            ack_hops=None,
            packets=(3, 3),
            incoming=True,
            done=True,
            received_at_ts=recv_ts,
        )
        self.assertEqual(
            ru,
            f"отправлено в {sent_hhmm} получено в {recv_hhmm} за 01:18, попытки 1, хопов 0, части 3/3",
        )

    def test_format_meta_delivered_shows_sent_and_delivered_time(self) -> None:
        sent_at_ts = 1700000000.0
        delivered_at_ts = sent_at_ts + 181.0
        sent_hhmm = time.strftime("%H:%M", time.localtime(sent_at_ts))
        delivered_hhmm = time.strftime("%H:%M", time.localtime(delivered_at_ts))
        ru = format_meta_text(
            "ru",
            delivery=181.0,
            attempts=1.0,
            forward_hops=0.0,
            ack_hops=0.0,
            packets=(1, 1),
            delivered_at_ts=delivered_at_ts,
            sent_at_ts=sent_at_ts,
        )
        self.assertEqual(
            ru,
            f"отправлена в {sent_hhmm} доставлено в {delivered_hhmm} за 03:01, с 1 попытки, хопы туда 0 обратно 0",
        )

    def test_snapshot_runtime_state_retries_and_succeeds(self) -> None:
        peers = _FlakyItemsDict(
            2,
            {
                "a": _State(10.0, 2),
                "b": _State(20.0, 4),
            },
        )
        peer_ids, avg_rtt = snapshot_runtime_state(peers, {"c": object()}, {"d"}, retries=4)
        self.assertEqual(peer_ids, {"a", "b", "c", "d"})
        self.assertAlmostEqual(avg_rtt, 15.0, places=3)

    def test_snapshot_runtime_state_fallback_on_persistent_errors(self) -> None:
        peer_ids, avg_rtt = snapshot_runtime_state(_AlwaysFailDict(), {"x": object()}, {"y"}, retries=2)
        self.assertEqual(peer_ids, set())
        self.assertEqual(avg_rtt, 0.0)

    def test_legacy_wire_chunking_roundtrip_utf8(self) -> None:
        text = "Привет мир " * 16
        created_s = 1700000000
        group_id = "1a2b3c4d"
        max_plain = 48
        chunks = build_legacy_chunks(text=text, max_plain=max_plain, created_s=created_s, group_id=group_id, attempts_hint=1)
        self.assertGreater(len(chunks), 1)
        rebuilt = []
        for idx, chunk in enumerate(chunks, start=1):
            payload = build_legacy_wire_payload(
                created_s=created_s,
                group_id=group_id,
                part=idx,
                total=len(chunks),
                attempt=1,
                chunk_text=chunk,
            )
            self.assertLessEqual(len(payload), max_plain)
            p_created, p_group, p_part, p_total, p_attempt, p_chunk = parse_legacy_wire_payload(payload)
            self.assertEqual(p_created, created_s)
            self.assertEqual(p_group, group_id)
            self.assertEqual(p_part, idx)
            self.assertEqual(p_total, len(chunks))
            self.assertEqual(p_attempt, 1)
            rebuilt.append(p_chunk)
        self.assertEqual("".join(rebuilt), text)

    def test_compact_wire_payload_fields(self) -> None:
        prefix = b"M2"
        created_s = 1700001234
        group_id = "89abcdef"
        payload = build_compact_wire_payload(
            prefix=prefix,
            created_s=created_s,
            group_id=group_id,
            part=2,
            total=5,
            attempt=3,
            compression_flag=1,
            chunk=b"xyz",
        )
        self.assertTrue(payload.startswith(prefix))
        self.assertEqual(len(payload), 16 + 3)
        self.assertEqual(struct.unpack(">I", payload[2:6])[0], created_s)
        self.assertEqual(payload[6:10], bytes.fromhex(group_id))
        part, total, attempt, meta = struct.unpack(">HHBB", payload[10:16])
        self.assertEqual((part, total, attempt, meta), (2, 5, 3, 1))
        self.assertEqual(payload[16:], b"xyz")

    def test_compact_wire_payload_group_fallback_hash(self) -> None:
        payload = build_compact_wire_payload(
            prefix=b"M2",
            created_s=10,
            group_id="bad-group-id",
            part=1,
            total=1,
            attempt=1,
            compression_flag=0,
            chunk=b"a",
        )
        expected_group = hashlib.sha256(b"bad-group-id").digest()[:4]
        self.assertEqual(payload[6:10], expected_group)

    def test_parse_compact_meta_new_compressed_flag(self) -> None:
        mc_block = compress_text("привет", mode=MODE_BYTE_DICT, preserve_case=True)
        compression, legacy_codec, label = parse_compact_meta(1, mc_block)
        self.assertEqual(compression, 1)
        self.assertEqual(legacy_codec, "deflate")
        self.assertEqual(label, "mc_byte_dict")

    def test_parse_compact_meta_legacy_meta1_without_magic(self) -> None:
        compression, legacy_codec, label = parse_compact_meta(1, b"\x01\x02\x03")
        self.assertEqual(compression, 0)
        self.assertEqual(legacy_codec, "deflate")
        self.assertEqual(label, "deflate")

    def test_parse_compact_meta_legacy_codec_id(self) -> None:
        compression, legacy_codec, label = parse_compact_meta(4)
        self.assertEqual(compression, 0)
        self.assertEqual(legacy_codec, "lzma")
        self.assertEqual(label, "lzma")

    def test_parse_key_exchange_frame_with_modes(self) -> None:
        pub_raw = bytes(range(32))
        pub_b64 = base64.b64encode(pub_raw)
        payload = b"KR1|!11223344|" + pub_b64 + b"|mc_modes=0,1,3,99"
        parsed = parse_key_exchange_frame(
            payload=payload,
            key_req_prefix=b"KR1|",
            key_resp_prefix=b"KR2|",
            supported_modes={0, 1, 2, 3, 4, 5},
        )
        self.assertIsNotNone(parsed)
        kind, peer_id, pub_out, peer_modes = parsed  # type: ignore[misc]
        self.assertEqual(kind, "req")
        self.assertEqual(peer_id, "!11223344")
        self.assertEqual(pub_out, pub_raw)
        self.assertEqual(peer_modes, {0, 1, 3})

    def test_parse_key_exchange_frame_without_modes(self) -> None:
        pub_raw = b"A" * 32
        pub_b64 = base64.b64encode(pub_raw)
        payload = b"KR2|!aabbccdd|" + pub_b64
        parsed = parse_key_exchange_frame(
            payload=payload,
            key_req_prefix=b"KR1|",
            key_resp_prefix=b"KR2|",
            supported_modes={0, 1, 2, 3, 4, 5},
        )
        self.assertIsNotNone(parsed)
        kind, peer_id, pub_out, peer_modes = parsed  # type: ignore[misc]
        self.assertEqual(kind, "resp")
        self.assertEqual(peer_id, "!aabbccdd")
        self.assertEqual(pub_out, pub_raw)
        self.assertIsNone(peer_modes)

    def test_parse_key_exchange_frame_invalid_payload(self) -> None:
        self.assertIsNone(
            parse_key_exchange_frame(
                payload=b"KR1|!deadbeef|not_base64",
                key_req_prefix=b"KR1|",
                key_resp_prefix=b"KR2|",
                supported_modes={0, 1},
            )
        )
        self.assertIsNone(
            parse_key_exchange_frame(
                payload=b"XX|abc",
                key_req_prefix=b"KR1|",
                key_resp_prefix=b"KR2|",
                supported_modes={0, 1},
            )
        )

    def test_parse_key_exchange_frame_invalid_key_length(self) -> None:
        short_pub = base64.b64encode(b"A" * 31)
        self.assertIsNone(
            parse_key_exchange_frame(
                payload=b"KR1|!deadbeef|" + short_pub,
                key_req_prefix=b"KR1|",
                key_resp_prefix=b"KR2|",
                supported_modes={0, 1},
            )
        )

    def test_validate_key_frame_source_unicast_ok(self) -> None:
        accepted, trusted, reason = validate_key_frame_source(
            peer_id="!11223344",
            from_id_raw="!11223344",
            is_broadcast=False,
        )
        self.assertTrue(accepted)
        self.assertTrue(trusted)
        self.assertEqual(reason, "")

    def test_validate_key_frame_source_unicast_case_insensitive(self) -> None:
        accepted, trusted, reason = validate_key_frame_source(
            peer_id="!AABBCCDD",
            from_id_raw="!aabbccdd",
            is_broadcast=False,
        )
        self.assertTrue(accepted)
        self.assertTrue(trusted)
        self.assertEqual(reason, "")

    def test_validate_key_frame_source_missing_from_id(self) -> None:
        accepted, trusted, reason = validate_key_frame_source(
            peer_id="!11223344",
            from_id_raw=None,
            is_broadcast=False,
        )
        self.assertFalse(accepted)
        self.assertFalse(trusted)
        self.assertEqual(reason, "missing_from_id")

    def test_validate_key_frame_source_mismatch(self) -> None:
        accepted, trusted, reason = validate_key_frame_source(
            peer_id="!11223344",
            from_id_raw="!55667788",
            is_broadcast=False,
        )
        self.assertFalse(accepted)
        self.assertFalse(trusted)
        self.assertEqual(reason, "id_mismatch")

    def test_validate_key_frame_source_broadcast_not_trusted(self) -> None:
        accepted, trusted, reason = validate_key_frame_source(
            peer_id="!11223344",
            from_id_raw="!11223344",
            is_broadcast=True,
        )
        self.assertTrue(accepted)
        self.assertFalse(trusted)
        self.assertEqual(reason, "")

    def test_key_frame_receive_policy_broadcast_disabled(self) -> None:
        accepted, trusted, reason, is_broadcast, from_id = key_frame_receive_policy(
            peer_id="!11223344",
            from_id_raw="!11223344",
            to_id="^all",
            broadcast_addr=0xFFFFFFFF,
            discovery_reply=False,
        )
        self.assertFalse(accepted)
        self.assertFalse(trusted)
        self.assertEqual(reason, "broadcast_disabled")
        self.assertTrue(is_broadcast)
        self.assertEqual(from_id, "!11223344")

    def test_key_frame_receive_policy_broadcast_allowed(self) -> None:
        accepted, trusted, reason, is_broadcast, from_id = key_frame_receive_policy(
            peer_id="!11223344",
            from_id_raw="!11223344",
            to_id="broadcast",
            broadcast_addr=0xFFFFFFFF,
            discovery_reply=True,
        )
        self.assertTrue(accepted)
        self.assertFalse(trusted)
        self.assertEqual(reason, "")
        self.assertTrue(is_broadcast)
        self.assertEqual(from_id, "!11223344")

    def test_key_frame_receive_policy_broadcast_addr_as_string(self) -> None:
        accepted, trusted, reason, is_broadcast, from_id = key_frame_receive_policy(
            peer_id="!11223344",
            from_id_raw="!11223344",
            to_id="^all",
            broadcast_addr="^all",
            discovery_reply=True,
        )
        self.assertTrue(accepted)
        self.assertFalse(trusted)
        self.assertEqual(reason, "")
        self.assertTrue(is_broadcast)
        self.assertEqual(from_id, "!11223344")

    def test_key_frame_receive_policy_unicast_mismatch(self) -> None:
        accepted, trusted, reason, is_broadcast, from_id = key_frame_receive_policy(
            peer_id="!11223344",
            from_id_raw="!55667788",
            to_id="!11223344",
            broadcast_addr=0xFFFFFFFF,
            discovery_reply=True,
        )
        self.assertFalse(accepted)
        self.assertFalse(trusted)
        self.assertEqual(reason, "id_mismatch")
        self.assertFalse(is_broadcast)
        self.assertEqual(from_id, "!55667788")

    def test_merge_compact_compression_never_downgrades_confirmed_mc(self) -> None:
        self.assertEqual(merge_compact_compression(0, 1), 1)
        self.assertEqual(merge_compact_compression(1, 0), 1)
        self.assertEqual(merge_compact_compression(1, 1), 1)
        self.assertEqual(merge_compact_compression(0, 0), 0)

    def test_looks_like_mc_block_is_strict(self) -> None:
        self.assertTrue(looks_like_mc_block(compress_text("ok", mode=MODE_BYTE_DICT, preserve_case=True)))
        self.assertFalse(looks_like_mc_block(b"MCpayload"))
        self.assertFalse(looks_like_mc_block(b"\x78\x9c\x00\x01"))

    def test_history_text_codec_roundtrip(self) -> None:
        text = "line1 | line2\nline3"
        encoded = encode_history_text(text)
        self.assertTrue(encoded.startswith("b64:"))
        self.assertEqual(decode_history_text(encoded), text)
        self.assertEqual(decode_history_text("plain text"), "plain text")

    def test_parse_history_line_strict_and_invalid(self) -> None:
        text = "группа | строка\nновая"
        encoded = encode_history_text(text)
        line = f"2026-02-08 12:00:00 | sent | group:test | 123 | {encoded}"
        parsed = parse_history_line(line, strict_encoded=True)
        self.assertIsNotNone(parsed)
        ts, direction, peer_id, msg_id, decoded_text = parsed  # type: ignore[misc]
        self.assertEqual(ts, "2026-02-08 12:00:00")
        self.assertEqual(direction, "sent")
        self.assertEqual(peer_id, "group:test")
        self.assertEqual(msg_id, "123")
        self.assertEqual(decoded_text, text)
        bad = "2026-02-08 12:00:00 | sent | group:test | 123 | b64:not_base64!"
        self.assertIsNone(parse_history_line(bad, strict_encoded=True))
        plain = "2026-02-08 12:00:00 | sent | group:test | 123 | plain text"
        self.assertIsNone(parse_history_line(plain, strict_encoded=True))
        with_extra = f"2026-02-08 12:00:00 | sent | group:test | 123 | {encoded} | extra"
        self.assertIsNone(parse_history_line(with_extra, strict_encoded=True))

    def test_assemble_compact_parts_out_of_order_mc(self) -> None:
        text = "Привет, это проверка out-of-order multipart MC."
        blob = compress_text(text, mode=MODE_BYTE_DICT, preserve_case=True)
        split_at = max(1, len(blob) // 2)
        c1 = blob[:split_at]
        c2 = blob[split_at:]
        parts = {
            "2": base64.b64encode(c2).decode("ascii"),
            "1": base64.b64encode(c1).decode("ascii"),
        }
        out, ok = assemble_compact_parts(parts, total=2, compression=1, legacy_codec="deflate", show_partial=True)
        self.assertTrue(ok)
        self.assertEqual(out, text)


if __name__ == "__main__":
    unittest.main()
