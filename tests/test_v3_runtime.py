import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from meshtalk.v3_runtime import (
    build_forward_relay_record,
    build_hop_ack_for_frame,
    build_prebuilt_relay_record,
    build_relay_plaintext_from_record,
    decode_hop_ack_part,
    duplicate_requires_hop_ack,
    pack_v3_record,
    pop_matching_relay_pending,
)
from meshtalk.relay_protocol import (
    RELAY_TYPE_CAPS,
    build_hop_ack_frame,
    build_token_adv_frame,
    current_epoch_slot,
    derive_relay_token,
    parse_frame,
)
from meshtalk.envelope_v3 import try_unpack_envelope_v3


class V3RuntimeTests(unittest.TestCase):
    def test_build_prebuilt_relay_record_extracts_frame_meta(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_300)
        raw = build_hop_ack_frame(
            msg_id=b"ABCDEFGH",
            return_token=derive_relay_token("deadbeef", epoch),
            frag_index=3,
            epoch_slot=epoch,
        )
        rec = build_prebuilt_relay_record(
            raw=raw,
            group_id="grp1",
            peer_id="deadbeef",
            route_reason="test",
            created_ts=123.0,
        )
        self.assertEqual(rec["relay_msg_hex"], "4142434445464748")
        self.assertEqual(rec["relay_frame_type"], "hop_ack")
        self.assertEqual(rec["part"], 3)
        self.assertEqual(rec["total"], 1)
        self.assertEqual(rec["peer"], "deadbeef")

    def test_pop_matching_relay_pending_removes_exact_part(self) -> None:
        peer_pending = {
            "a": {"relay_v3": True, "relay_msg_hex": "4142434445464748", "part": 1},
            "b": {"relay_v3": True, "relay_msg_hex": "4142434445464748", "part": 2},
            "c": {"relay_v3": False, "relay_msg_hex": "4142434445464748", "part": 2},
        }
        pending_id, rec = pop_matching_relay_pending(
            peer_pending,
            frame_msg_id=b"ABCDEFGH",
            frame_part=2,
        )
        self.assertEqual(pending_id, "b")
        self.assertEqual(rec["part"], 2)
        self.assertIn("a", peer_pending)
        self.assertNotIn("b", peer_pending)

    def test_pack_v3_record_roundtrip(self) -> None:
        aes = AESGCM(b"\x33" * 32)
        epoch = current_epoch_slot(now=1_700_000_301)
        rec = {
            "id": "0011223344556677",
            "relay_v3": True,
            "relay_msg_hex": "4142434445464748",
            "relay_body_b64": "aGVsbG8=",
            "relay_token_b64": "QUJDREVGR0g=",
            "relay_return_token_b64": "SEdGRURDQkE=",
            "relay_ttl": 5,
            "part": 1,
            "total": 1,
            "created": float(epoch * 900),
        }
        pt = build_relay_plaintext_from_record(rec, now=float(epoch * 900))
        self.assertTrue(pt)
        wire = pack_v3_record(rec, aes, now=float(epoch * 900))
        status, _, inner = try_unpack_envelope_v3(wire, aes)
        self.assertEqual(status, "ok")
        self.assertEqual(inner, pt)

    def test_build_hop_ack_for_frame(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_302)
        frame = parse_frame(
            build_hop_ack_frame(
                msg_id=b"ABCDEFGH",
                return_token=derive_relay_token("deadbeef", epoch),
                frag_index=4,
                epoch_slot=epoch,
            )
        )
        self.assertIsNotNone(frame)
        ack = parse_frame(build_hop_ack_for_frame(frame))
        self.assertIsNotNone(ack)
        assert ack is not None
        self.assertEqual(ack.body, b"\x00\x04")

    def test_decode_hop_ack_part_and_duplicate_policy(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_303)
        frame = parse_frame(
            build_hop_ack_frame(
                msg_id=b"ABCDEFGH",
                return_token=derive_relay_token("deadbeef", epoch),
                frag_index=7,
                epoch_slot=epoch,
            )
        )
        self.assertIsNotNone(frame)
        assert frame is not None
        self.assertEqual(decode_hop_ack_part(frame), 7)
        self.assertFalse(duplicate_requires_hop_ack(frame.frame_type))
        self.assertTrue(duplicate_requires_hop_ack(RELAY_TYPE_CAPS))
        self.assertFalse(duplicate_requires_hop_ack(255))

    def test_build_forward_relay_record(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_304)
        frame = parse_frame(
            build_hop_ack_frame(
                msg_id=b"ABCDEFGH",
                return_token=derive_relay_token("deadbeef", epoch),
                frag_index=2,
                epoch_slot=epoch,
            )
        )
        self.assertIsNotNone(frame)
        assert frame is not None
        rec = build_forward_relay_record(
            frame_obj=frame,
            next_peer="cafebabe",
            raw_forwarded=b"xyz",
            created_ts=55.0,
            route_reason="relay_forward",
        )
        self.assertEqual(rec["peer"], "cafebabe")
        self.assertEqual(rec["relay_msg_hex"], "4142434445464748")
        self.assertEqual(rec["relay_frame_type"], "hop_ack")
        self.assertEqual(rec["part"], 1)
        self.assertEqual(rec["total"], 1)

    def test_build_prebuilt_relay_record_marks_token_adv_no_retry(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_305)
        raw = build_token_adv_frame(
            relay_token=derive_relay_token("deadbeef", epoch),
            reach_score=1000,
            ttl=4,
            epoch_slot=epoch,
        )
        rec = build_prebuilt_relay_record(
            raw=raw,
            group_id="grp2",
            peer_id="deadbeef",
            route_reason="token_adv",
            created_ts=123.0,
        )
        self.assertEqual(rec["relay_frame_type"], "token_adv")
        self.assertTrue(rec["no_retry"])


if __name__ == "__main__":
    unittest.main()
