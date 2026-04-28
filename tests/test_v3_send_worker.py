import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from meshtalk.v3_send_worker import SendWindowState, V3SendWorker


class _PeerState:
    def __init__(self, *, key_ready=True, force_key_req=False, aes=None):
        self.key_ready = key_ready
        self.force_key_req = force_key_req
        self.aes = aes
        self.next_key_req_ts = 0.0


class V3SendWorkerTests(unittest.TestCase):
    def test_none_when_no_candidates(self) -> None:
        worker = V3SendWorker(SendWindowState())
        action = worker.next_action(
            now=10.0,
            rate_s=0.0,
            parallel=1,
            intra_gap_s=0.0,
            pending_by_peer={},
            tracked_peers=[],
            get_peer_state=lambda _peer: None,
            norm_id_for_filename=lambda s: s,
            self_id="self",
            max_seconds=60.0,
            max_plain=100,
            max_bytes=100,
            build_wire_pt_fn=lambda rec, attempt: b"",
            pack_payload_fn=lambda rec, st, ts: b"",
        )
        self.assertEqual(action.kind, "none")

    def test_key_request_due_and_set_self_aes(self) -> None:
        states = {
            "self": _PeerState(key_ready=False, force_key_req=True, aes=None),
            "peer": _PeerState(key_ready=False, force_key_req=True, aes=None),
        }
        worker = V3SendWorker(SendWindowState())
        action = worker.next_action(
            now=10.0,
            rate_s=0.0,
            parallel=1,
            intra_gap_s=0.0,
            pending_by_peer={"self": {}, "peer": {}},
            tracked_peers=["self", "peer"],
            get_peer_state=lambda peer: states.get(peer),
            norm_id_for_filename=lambda s: s,
            self_id="self",
            max_seconds=60.0,
            max_plain=100,
            max_bytes=100,
            build_wire_pt_fn=lambda rec, attempt: b"",
            pack_payload_fn=lambda rec, st, ts: b"",
        )
        self.assertEqual(action.kind, "key_request_due")
        self.assertEqual(action.peer_norm, "peer")

    def test_timeout_drop(self) -> None:
        states = {"peer": _PeerState(key_ready=True, aes=AESGCM(b"\x11" * 32))}
        worker = V3SendWorker(SendWindowState())
        action = worker.next_action(
            now=100.0,
            rate_s=0.0,
            parallel=1,
            intra_gap_s=0.0,
            pending_by_peer={"peer": {"1": {"id": "1", "created": 0.0}}},
            tracked_peers=[],
            get_peer_state=lambda peer: states.get(peer),
            norm_id_for_filename=lambda s: s,
            self_id="self",
            max_seconds=10.0,
            max_plain=100,
            max_bytes=100,
            build_wire_pt_fn=lambda rec, attempt: b"abc",
            pack_payload_fn=lambda rec, st, ts: b"abc",
        )
        self.assertEqual(action.kind, "timeout_drop")
        self.assertEqual(action.peer_norm, "peer")

    def test_send_ready(self) -> None:
        states = {"peer": _PeerState(key_ready=True, aes=AESGCM(b"\x11" * 32))}
        worker = V3SendWorker(SendWindowState())
        action = worker.next_action(
            now=10.0,
            rate_s=0.0,
            parallel=1,
            intra_gap_s=0.0,
            pending_by_peer={"peer": {"1": {"id": "1", "created": 5.0, "attempts": 0, "text": "hi", "cmp": "none", "next_retry_at": 0.0}}},
            tracked_peers=[],
            get_peer_state=lambda peer: states.get(peer),
            norm_id_for_filename=lambda s: s,
            self_id="self",
            max_seconds=60.0,
            max_plain=100,
            max_bytes=100,
            build_wire_pt_fn=lambda rec, attempt: b"abc",
            pack_payload_fn=lambda rec, st, ts: b"payload",
        )
        self.assertEqual(action.kind, "send_ready")
        self.assertEqual(action.peer_norm, "peer")
        self.assertEqual(action.payload, b"payload")
        worker.mark_sent(now=10.0, rr_next_offset=2)
        self.assertEqual(worker.state.count, 1)
        self.assertEqual(worker.state.last_tx_ts, 10.0)
        self.assertEqual(worker.state.rr_offset, 2)

    def test_data_is_prioritized_over_control(self) -> None:
        states = {"peer": _PeerState(key_ready=True, aes=AESGCM(b"\x11" * 32))}
        worker = V3SendWorker(SendWindowState())
        action = worker.next_action(
            now=10.0,
            rate_s=0.0,
            parallel=1,
            intra_gap_s=0.0,
            pending_by_peer={
                "peer": {
                    "1": {
                        "id": "1",
                        "created": 1.0,
                        "attempts": 0,
                        "text": "",
                        "cmp": "none",
                        "next_retry_at": 0.0,
                        "relay_frame_type": "token_adv",
                    },
                    "2": {
                        "id": "2",
                        "created": 9.0,
                        "attempts": 0,
                        "text": "payload",
                        "cmp": "none",
                        "next_retry_at": 0.0,
                        "relay_frame_type": "data",
                    },
                }
            },
            tracked_peers=[],
            get_peer_state=lambda peer: states.get(peer),
            norm_id_for_filename=lambda s: s,
            self_id="self",
            max_seconds=60.0,
            max_plain=100,
            max_bytes=100,
            build_wire_pt_fn=lambda rec, attempt: (str(rec.get("id")).encode("ascii")),
            pack_payload_fn=lambda rec, st, ts: (str(rec.get("id")).encode("ascii")),
        )
        self.assertEqual(action.kind, "send_ready")
        self.assertEqual(action.rec["id"], "2")

    def test_data_groups_alternate_for_same_peer(self) -> None:
        states = {"peer": _PeerState(key_ready=True, aes=AESGCM(b"\x11" * 32))}
        worker = V3SendWorker(SendWindowState(last_group_by_peer={"peer": "g1"}))
        action = worker.next_action(
            now=10.0,
            rate_s=0.0,
            parallel=1,
            intra_gap_s=0.0,
            pending_by_peer={
                "peer": {
                    "1": {
                        "id": "1",
                        "created": 1.0,
                        "attempts": 0,
                        "text": "a",
                        "cmp": "none",
                        "next_retry_at": 0.0,
                        "relay_frame_type": "data",
                        "group_id": "g1",
                        "part": 1,
                    },
                    "2": {
                        "id": "2",
                        "created": 2.0,
                        "attempts": 0,
                        "text": "b",
                        "cmp": "none",
                        "next_retry_at": 0.0,
                        "relay_frame_type": "data",
                        "group_id": "g2",
                        "part": 1,
                    },
                }
            },
            tracked_peers=[],
            get_peer_state=lambda peer: states.get(peer),
            norm_id_for_filename=lambda s: s,
            self_id="self",
            max_seconds=60.0,
            max_plain=100,
            max_bytes=100,
            build_wire_pt_fn=lambda rec, attempt: (str(rec.get("id")).encode("ascii")),
            pack_payload_fn=lambda rec, st, ts: (str(rec.get("id")).encode("ascii")),
        )
        self.assertEqual(action.kind, "send_ready")
        self.assertEqual(action.rec["id"], "2")
        worker.mark_sent(now=10.0, rr_next_offset=0, peer_norm="peer", group_key="g2")
        self.assertEqual(worker.state.last_group_by_peer.get("peer"), "g2")


if __name__ == "__main__":
    unittest.main()
