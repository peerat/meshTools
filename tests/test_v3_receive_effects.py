import unittest

from meshtalk.relay_protocol import (
    build_data_frame,
    build_end_ack_frame,
    build_hop_ack_frame,
    build_token_adv_frame,
    current_epoch_slot,
    derive_relay_token,
    parse_frame,
)
from meshtalk.v3_receive_effects import (
    handle_ack_effects,
    handle_data_forward_effects,
    handle_data_local_delivery_effects,
    handle_token_adv_effects,
)


class V3ReceiveEffectsTests(unittest.TestCase):
    def test_handle_ack_effects(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_700)
        token = derive_relay_token("cafebabe", epoch)
        frame = parse_frame(build_end_ack_frame(msg_id=b"ABCDEFGH", return_token=token, ttl=3, epoch_slot=epoch))
        self.assertIsNotNone(frame)
        assert frame is not None
        consumed = []
        queued = []
        emits = []
        handle_ack_effects(
            relay_frame=frame,
            ack_plan={"ack_part": 1, "delivered_local": False, "next_peers": ["cafebabe"]},
            peer_norm="deadbeef",
            consume_hop_ack_fn=lambda *args: consumed.append(args),
            queue_relay_prebuilt_fn=lambda peer, raw: queued.append((peer, raw)) or True,
            serialize_decremented_fn=lambda fr: b"raw",
            ui_emit_fn=lambda kind, payload: emits.append((kind, payload)),
            ts_local_fn=lambda: "TS",
        )
        self.assertFalse(consumed)
        self.assertEqual(queued[0][0], "cafebabe")
        self.assertEqual(emits[0][0], "log")
        self.assertEqual(len(emits), 1)
        self.assertIn("end_ack fwd", emits[0][1])

    def test_handle_hop_ack_emits_ui_ack(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_700)
        token = derive_relay_token("cafebabe", epoch)
        frame = parse_frame(build_hop_ack_frame(msg_id=b"ABCDEFGH", return_token=token, frag_index=2, epoch_slot=epoch))
        self.assertIsNotNone(frame)
        assert frame is not None
        emits = []
        removed = {
            "relay_msg_hex": "4142434445464748",
            "group": "4142434445464748",
            "created": 1_700_000_690.0,
            "attempts": 1,
            "total": 4,
        }
        handle_ack_effects(
            relay_frame=frame,
            ack_plan={"ack_part": 2, "delivered_local": False, "next_peers": []},
            peer_norm="deadbeef",
            consume_hop_ack_fn=lambda *args: removed,
            queue_relay_prebuilt_fn=lambda peer, raw: True,
            serialize_decremented_fn=lambda fr: b"raw",
            ui_emit_fn=lambda kind, payload: emits.append((kind, payload)),
            ts_local_fn=lambda: "TS",
        )
        self.assertEqual(emits[0][0], "ack")
        self.assertEqual(emits[0][1][0], "deadbeef")
        self.assertEqual(emits[0][1][1], "4142434445464748")
        self.assertEqual(emits[0][1][4], 4)
        self.assertEqual(len(emits), 1)

    def test_handle_duplicate_hop_ack_suppresses_log(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_700)
        token = derive_relay_token("cafebabe", epoch)
        frame = parse_frame(build_hop_ack_frame(msg_id=b"ABCDEFGH", return_token=token, frag_index=2, epoch_slot=epoch))
        self.assertIsNotNone(frame)
        assert frame is not None
        emits = []
        handle_ack_effects(
            relay_frame=frame,
            ack_plan={"ack_part": 2, "delivered_local": False, "next_peers": []},
            peer_norm="deadbeef",
            consume_hop_ack_fn=lambda *args: None,
            queue_relay_prebuilt_fn=lambda peer, raw: True,
            serialize_decremented_fn=lambda fr: b"raw",
            ui_emit_fn=lambda kind, payload: emits.append((kind, payload)),
            ts_local_fn=lambda: "TS",
        )
        self.assertEqual(emits, [])

    def test_handle_token_adv_effects(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_701)
        token = derive_relay_token("cafebabe", epoch)
        frame = parse_frame(build_token_adv_frame(relay_token=token, reach_score=1000, ttl=3, epoch_slot=epoch))
        self.assertIsNotNone(frame)
        assert frame is not None
        queued = []
        emits = []
        handle_token_adv_effects(
            relay_frame=frame,
            token_adv_plan={
                "adv_score": 1000,
                "next_peers": ["cafebabe"],
                "route_update": {"changed": True, "prev_best": "", "best_via": "deadbeef", "candidates": ["deadbeef"]},
            },
            peer_norm="deadbeef",
            queue_relay_prebuilt_fn=lambda peer, raw: queued.append((peer, raw)) or True,
            serialize_decremented_fn=lambda fr: b"raw",
            ui_emit_fn=lambda kind, payload: emits.append((kind, payload)),
            ts_local_fn=lambda: "TS",
        )
        self.assertEqual(queued[0][0], "cafebabe")
        self.assertEqual(len(emits), 3)
        self.assertIn("route_learn", emits[0][1])
        self.assertIn("route_best", emits[1][1])
        self.assertIn("route_adv fwd", emits[2][1])

    def test_handle_token_adv_effects_dedups_rx_log(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_701)
        token = derive_relay_token("cafebabe", epoch)
        frame = parse_frame(build_token_adv_frame(relay_token=token, reach_score=1000, ttl=3, epoch_slot=epoch))
        self.assertIsNotNone(frame)
        assert frame is not None
        emits = []
        handle_token_adv_effects(
            relay_frame=frame,
            token_adv_plan={"adv_score": 1000, "next_peers": []},
            peer_norm="feedface",
            queue_relay_prebuilt_fn=lambda peer, raw: True,
            serialize_decremented_fn=lambda fr: b"raw",
            ui_emit_fn=lambda kind, payload: emits.append((kind, payload)),
            ts_local_fn=lambda: "TS",
        )
        handle_token_adv_effects(
            relay_frame=frame,
            token_adv_plan={"adv_score": 1000, "next_peers": []},
            peer_norm="feedface",
            queue_relay_prebuilt_fn=lambda peer, raw: True,
            serialize_decremented_fn=lambda fr: b"raw",
            ui_emit_fn=lambda kind, payload: emits.append((kind, payload)),
            ts_local_fn=lambda: "TS",
        )
        self.assertEqual(len(emits), 1)
        self.assertEqual(emits[0][0], "log")
        self.assertIn("route_learn", emits[0][1])

    def test_handle_data_local_delivery_effects(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_702)
        token = derive_relay_token("cafebabe", epoch)
        frame = parse_frame(build_data_frame(msg_id=b"ABCDEFGH", relay_token=token, return_token=token, body=b"x", ttl=3, frag_index=1, frag_total=1, epoch_slot=epoch))
        self.assertIsNotNone(frame)
        assert frame is not None
        incoming = {"deadbeef:4142434445464748": {"parts": {1: b"x"}}}
        emits = []
        end_acks = []
        handle_data_local_delivery_effects(
            relay_frame=frame,
            peer_norm="deadbeef",
            recv_event=("deadbeef", "hello"),
            relay_incoming=incoming,
            send_end_ack_fn=lambda fr: end_acks.append(fr.msg_id.hex()) or True,
            ui_emit_fn=lambda kind, payload: emits.append((kind, payload)),
        )
        self.assertEqual(emits[0][0], "recv")
        self.assertEqual(end_acks[0], "4142434445464748")
        self.assertEqual(incoming, {})

    def test_handle_data_forward_effects(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_703)
        token = derive_relay_token("cafebabe", epoch)
        frame = parse_frame(build_data_frame(msg_id=b"ABCDEFGH", relay_token=token, return_token=token, body=b"x", ttl=3, frag_index=1, frag_total=1, epoch_slot=epoch))
        self.assertIsNotNone(frame)
        assert frame is not None
        adds = []
        emits = []
        handle_data_forward_effects(
            relay_frame=frame,
            next_peers=["cafebabe", "deadbeef"],
            add_forward_record_fn=lambda peer, raw: adds.append((peer, raw)),
            serialize_decremented_fn=lambda fr: b"raw",
            ui_emit_fn=lambda kind, payload: emits.append((kind, payload)),
            ts_local_fn=lambda: "TS",
        )
        self.assertEqual([x[0] for x in adds], ["cafebabe", "deadbeef"])
        self.assertEqual(emits[0][0], "log")


if __name__ == "__main__":
    unittest.main()
