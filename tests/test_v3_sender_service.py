import unittest

from meshtalk.v3_sender_service import (
    finalize_send_success,
    finalize_send_success_direct,
    process_non_send_action,
    process_non_send_action_direct,
)


class _Action:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class _PeerState:
    def __init__(self):
        self.aes = None
        self.last_key_req_ts = 0.0
        self.next_key_req_ts = 0.0
        self.rekey_sent_msgs = 0


class V3SenderServiceTests(unittest.TestCase):
    def test_process_non_send_action(self) -> None:
        st = _PeerState()
        calls = []
        res = process_non_send_action(
            action=_Action(kind="key_request_due", peer_norm="peer"),
            now=10.0,
            get_peer_state=lambda _peer: st,
            derive_key_fn=lambda a, b: b"k" * 32,
            priv=object(),
            pub_self=object(),
            wire_id_from_norm=lambda p: f"!{p}",
            send_key_request_fn=lambda peer: calls.append(("kr", peer)),
            retry_seconds=30.0,
            ts_local_fn=lambda: "TS",
            print_fn=lambda msg: calls.append(("print", msg)),
            timeout_drop_fn=lambda act: calls.append(("timeout", act.kind)),
            drop_fn=lambda act: calls.append(("drop", act.kind)),
        )
        self.assertEqual(res, "continue")
        self.assertEqual(calls[0][0], "print")
        self.assertEqual(calls[1], ("kr", "peer"))
        self.assertEqual(st.next_key_req_ts, 40.0)

    def test_finalize_send_success(self) -> None:
        st = _PeerState()
        calls = []
        action = _Action(kind="send_ready", peer_norm="peer", rec={"id": "1", "relay_frame_type": "data"}, payload=b"abc", text="hi", cmp_name="none", attempts_next=2, rr_next_offset=3)
        ok = finalize_send_success(
            action=action,
            now=10.0,
            get_peer_state=lambda _peer: st,
            metrics_inc_fn=lambda name, value: calls.append(("metric", name, value)),
            activity_record_fn=lambda size: calls.append(("activity", size)),
            post_send_state_fn=lambda rec, peer_state, attempts: calls.append(("post", attempts)),
            commit_send_fn=lambda peer_norm, rec, text, cmp_name: calls.append(("commit", peer_norm, text, cmp_name)),
            mark_sent_fn=lambda now, rr: calls.append(("mark", now, rr)),
        )
        self.assertTrue(ok)
        self.assertEqual(st.rekey_sent_msgs, 1)
        self.assertEqual(calls[0], ("activity", 3))
        self.assertEqual(calls[1], ("metric", "out_send", 1.0))
        self.assertEqual(calls[2], ("metric", "out_retry", 1.0))
        self.assertEqual(calls[3], ("post", 2))
        self.assertEqual(calls[4], ("commit", "peer", "hi", "none"))
        self.assertEqual(calls[5], ("mark", 10.0, 3))

    def test_finalize_send_success_does_not_count_control_for_rekey(self) -> None:
        st = _PeerState()
        action = _Action(kind="send_ready", peer_norm="peer", rec={"id": "1", "relay_frame_type": "caps"}, payload=b"x", text="", cmp_name="none", attempts_next=1, rr_next_offset=0)
        ok = finalize_send_success(
            action=action,
            now=10.0,
            get_peer_state=lambda _peer: st,
            metrics_inc_fn=lambda *_args: None,
            activity_record_fn=lambda *_args: None,
            post_send_state_fn=lambda *_args: None,
            commit_send_fn=lambda *_args: None,
            mark_sent_fn=lambda *_args: None,
        )
        self.assertTrue(ok)
        self.assertEqual(st.rekey_sent_msgs, 0)

    def test_process_non_send_action_direct(self) -> None:
        st = _PeerState()
        calls = []
        pending = {"peer": {"1": {"id": "1", "text": "x"}}}
        res = process_non_send_action_direct(
            action=_Action(kind="drop", peer_norm="peer", rec={"id": "1", "text": "x"}, text="x", reason="too_long"),
            now=10.0,
            get_peer_state=lambda _peer: st,
            derive_key_fn=lambda a, b: b"k" * 32,
            priv=object(),
            pub_self=object(),
            wire_id_from_norm=lambda p: f"!{p}",
            send_key_request_base_fn=lambda peer, require_confirm, reason: calls.append(("kr", peer, require_confirm, reason)),
            retry_seconds=30.0,
            ts_local_fn=lambda: "TS",
            print_fn=lambda msg: calls.append(("print", msg)),
            pending_by_peer=pending,
            save_state_fn=lambda _state: calls.append(("save", True)),
            append_history_fn=lambda *args: calls.append(("hist", args[0], args[1], args[4])),
            pacer=object(),
            routing_ctl=object(),
            ui_emit_fn=lambda name, payload: calls.append(("emit", name)),
        )
        self.assertEqual(res, "continue")
        self.assertEqual(calls[0][0], "print")
        self.assertFalse(pending)

    def test_finalize_send_success_direct(self) -> None:
        st = _PeerState()
        calls = []
        action = _Action(kind="send_ready", peer_norm="peer", rec={"id": "1", "attempts": 0, "relay_frame_type": "data"}, payload=b"abc", text="hi", cmp_name="none", attempts_next=1, rr_next_offset=2)
        class _SendWorker:
            def mark_sent(self, *, now, rr_next_offset, peer_norm="", group_key=""):
                calls.append(("mark", now, rr_next_offset, peer_norm, group_key))

        ok = finalize_send_success_direct(
            action=action,
            now=10.0,
            get_peer_state=lambda _peer: st,
            metrics_inc_base_fn=lambda name, value, now: calls.append(("metric", name, value, now)),
            activity_record_base_fn=lambda direction, kind, count, now, bytes_count: calls.append(("activity", direction, kind, count, now, bytes_count)),
            schedule_next_retry_fn=lambda rec, peer_state, now, retry_seconds, attempts: 5.0,
            retry_seconds=30.0,
            cfg={},
            peer_meta={},
            pending_by_peer={},
            save_state_fn=lambda _state: calls.append(("save", True)),
            append_history_fn=lambda *args: calls.append(("hist", args[0], args[1])),
            ui_emit_fn=lambda name, payload: calls.append(("emit", name)),
            ts_local_fn=lambda: "TS",
            proto_version=3,
            send_worker=_SendWorker(),
        )
        self.assertTrue(ok)
        self.assertEqual(st.rekey_sent_msgs, 1)
        self.assertIn(("mark", 10.0, 2, "peer", ""), calls)


if __name__ == "__main__":
    unittest.main()
