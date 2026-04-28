import unittest
from contextlib import nullcontext

from meshtalk.relay_protocol import build_data_frame, build_hop_ack_frame, build_token_adv_frame, parse_frame
from meshtalk.v3_receiver_service import (
    process_ack_frame,
    process_ack_frame_direct,
    process_data_frame,
    process_data_frame_direct,
    process_token_adv_frame,
    process_token_adv_frame_direct,
)


class V3ReceiverServiceTests(unittest.TestCase):
    def test_process_ack_and_token_adv(self) -> None:
        calls = []
        frame = object()
        process_ack_frame(
            relay_frame=frame,
            peer_norm="peer",
            ack_plan_fn=lambda fr: {"x": 1},
            ack_effects_fn=lambda fr, plan: calls.append(("ack", fr, plan)),
        )
        process_token_adv_frame(
            relay_frame=frame,
            token_adv_plan_fn=lambda fr: {"y": 2},
            token_adv_effects_fn=lambda fr, plan: calls.append(("adv", fr, plan)),
        )
        self.assertEqual(calls[0][0], "ack")
        self.assertEqual(calls[1][0], "adv")

    def test_process_data_frame(self) -> None:
        calls = []
        frame = object()
        process_data_frame(
            relay_frame=frame,
            ingest_fn=lambda fr: ({"rec": 1}, True),
            local_deliver=True,
            decode_local_fn=lambda rec: ("evt", rec),
            local_effects_fn=lambda fr, evt: calls.append(("local", evt)),
            forward_plan_fn=lambda fr: ["peer"],
            forward_effects_fn=lambda fr, peers: calls.append(("forward", peers)),
        )
        self.assertEqual(calls[0][0], "local")
        calls.clear()
        process_data_frame(
            relay_frame=frame,
            ingest_fn=lambda fr: ({"rec": 1}, False),
            local_deliver=False,
            decode_local_fn=lambda rec: ("evt", rec),
            local_effects_fn=lambda fr, evt: calls.append(("local", evt)),
            forward_plan_fn=lambda fr: ["peer"],
            forward_effects_fn=lambda fr, peers: calls.append(("forward", peers)),
        )
        self.assertEqual(calls[0], ("forward", ["peer"]))

    def test_direct_ack_and_token_adv(self) -> None:
        calls = []

        class _RelayState:
            def should_forward(self, **kwargs):
                return True, ["n1"]

            def mark_seen(self, *args, **kwargs):
                return None

            def learn_token(self, *args, **kwargs):
                return None

        ack = parse_frame(build_hop_ack_frame(msg_id=b"\x01" * 8, return_token=b"\x09" * 8, frag_index=2))
        process_ack_frame_direct(
            relay_frame=ack,
            relay_state=_RelayState(),
            peer_norm="peer",
            ack_part=2,
            token_matches_self=False,
            consume_hop_ack_fn=lambda msg_id, part, reason: calls.append(("consume", part, reason)),
            queue_relay_prebuilt_fn=lambda peer, payload, group, reason: calls.append(("queue", peer, group, reason)) or True,
            ui_emit_fn=lambda name, payload: calls.append(("emit", name)),
            ts_local_fn=lambda: "TS",
        )
        adv = parse_frame(build_token_adv_frame(relay_token=b"\x02" * 8, ttl=3, reach_score=7))
        process_token_adv_frame_direct(
            relay_frame=adv,
            relay_state=_RelayState(),
            peer_norm="peer",
            now=10.0,
            queue_relay_prebuilt_fn=lambda peer, payload, group, reason: calls.append(("queue", peer, group, reason)) or True,
            ui_emit_fn=lambda name, payload: calls.append(("emit", name)),
            ts_local_fn=lambda: "TS",
        )
        self.assertEqual(calls[0], ("consume", 2, "hop_ack"))
        self.assertTrue(any(c[:2] == ("emit", "log") for c in calls))

    def test_process_data_frame_direct(self) -> None:
        calls = []

        class _RelayState:
            def should_forward(self, **kwargs):
                return True, ["peer2"]

        msg_id = b"\x03" * 8
        token = b"\x04" * 8
        ret = b"\x05" * 8
        frame = parse_frame(build_data_frame(
            msg_id=msg_id,
            relay_token=token,
            return_token=ret,
            body=b"hello",
            ttl=3,
            frag_index=1,
            frag_total=1,
        ))
        relay_incoming = {}
        forwarded = process_data_frame_direct(
            relay_frame=frame,
            relay_incoming=relay_incoming,
            peer_norm="peer",
            packet={"hopLimit": 3},
            local_deliver=True,
            relay_state=_RelayState(),
            now=10.0,
            decompress_text_fn=lambda body: (body.decode("utf-8"), "none"),
            from_id="peer-wire",
            peer_state=object(),
            send_relay_control_frame_fn=lambda _peer, _state, ack: calls.append(("endack", len(ack))) or True,
            pending_by_peer={},
            pending_lock=nullcontext(),
            save_state_fn=lambda state: calls.append(("save", bool(state))),
            ui_emit_fn=lambda name, payload: calls.append((name, payload[0] if isinstance(payload, tuple) else payload)),
            ts_local_fn=lambda: "TS",
        )
        self.assertFalse(forwarded)
        self.assertTrue(any(c[0] == "recv" for c in calls))
        frame2 = parse_frame(build_data_frame(
            msg_id=b"\x06" * 8,
            relay_token=token,
            return_token=ret,
            body=b"abc",
            ttl=3,
            frag_index=1,
            frag_total=2,
        ))
        pending = {}
        forwarded2 = process_data_frame_direct(
            relay_frame=frame2,
            relay_incoming={},
            peer_norm="peer",
            packet={},
            local_deliver=False,
            relay_state=_RelayState(),
            now=10.0,
            decompress_text_fn=lambda body: (body.decode("utf-8"), "none"),
            from_id="peer-wire",
            peer_state=object(),
            send_relay_control_frame_fn=lambda _peer, _state, ack: True,
            pending_by_peer=pending,
            pending_lock=nullcontext(),
            save_state_fn=lambda state: calls.append(("save", bool(state))),
            ui_emit_fn=lambda name, payload: calls.append((name, payload)),
            ts_local_fn=lambda: "TS",
        )
        self.assertTrue(forwarded2)
        self.assertTrue(any(c[0] == "save" for c in calls))
        self.assertIn("peer2", pending)


if __name__ == "__main__":
    unittest.main()
