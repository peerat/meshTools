import unittest

from meshtalk.v3_send_effects import handle_drop_action, handle_send_success, handle_timeout_drop_action, remove_pending_record


class _Action:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class _Pacer:
    def __init__(self):
        self.calls = []

    def observe_drop(self, reason, now=None):
        self.calls.append((reason, now))


class _Routing:
    def __init__(self):
        self.calls = []

    def observe_tx_result(self, *args, **kwargs):
        self.calls.append((args, kwargs))


class V3SendEffectsTests(unittest.TestCase):
    def test_remove_pending_record(self) -> None:
        pending = {"peer": {"1": {"id": "1"}}}
        remove_pending_record(pending, peer_norm="peer", rec_id="1")
        self.assertEqual(pending, {})

    def test_handle_timeout_drop_action(self) -> None:
        pending = {"peer": {"1": {"id": "1", "group": "g", "attempts": 2, "total": 1, "route_id": "relay_v3", "micro_retries_sent": 0, "text": "hello"}}}
        hist = []
        emits = []
        pacer = _Pacer()
        routing = _Routing()
        action = _Action(peer_norm="peer", rec=pending["peer"]["1"])
        handle_timeout_drop_action(
            action=action,
            pending_by_peer=pending,
            save_state_fn=lambda state: None,
            append_history_fn=lambda *args: hist.append(args),
            pacer=pacer,
            routing_ctl=routing,
            ui_emit_fn=lambda kind, payload: emits.append((kind, payload)),
            ts_local_fn=lambda: "TS",
            now=10.0,
        )
        self.assertEqual(pending, {})
        self.assertEqual(hist[0][0], "drop")
        self.assertEqual(pacer.calls[0][0], "timeout")
        self.assertTrue(routing.calls)
        self.assertEqual(emits[0][0], "log")
        self.assertEqual(emits[1][0], "failed")

    def test_handle_drop_and_send_success(self) -> None:
        pending = {"peer": {"1": {"id": "1", "group": "g", "attempts": 0, "total": 1}}}
        hist = []
        emits = []
        action = _Action(peer_norm="peer", rec=pending["peer"]["1"], text="txt", reason="payload_too_big")
        handle_drop_action(
            action=action,
            pending_by_peer=pending,
            save_state_fn=lambda state: None,
            append_history_fn=lambda *args: hist.append(args),
            ui_emit_fn=lambda kind, payload: emits.append((kind, payload)),
            ts_local_fn=lambda: "TS",
        )
        self.assertEqual(pending, {})
        self.assertEqual(hist[0][4], "payload_too_big")
        self.assertEqual(emits[0][0], "log")
        self.assertEqual(emits[1][0], "failed")

        pending2 = {}
        rec = {"id": "2", "attempts": 1}
        hist2 = []
        emits2 = []
        handle_send_success(
            peer_norm="peer",
            rec=rec,
            text="hi",
            cmp_name="none",
            pending_by_peer=pending2,
            save_state_fn=lambda state: None,
            append_history_fn=lambda *args: hist2.append(args),
            ui_emit_fn=lambda kind, payload: emits2.append((kind, payload)),
            ts_local_fn=lambda: "TS",
            proto_version=3,
        )
        self.assertIn("peer", pending2)
        self.assertEqual(hist2[0][0], "send")
        self.assertEqual(emits2[0][0], "log")

        pending3 = {"peer": {"3": {"id": "3", "attempts": 1, "no_retry": True}}}
        rec3 = pending3["peer"]["3"]
        hist3 = []
        emits3 = []
        handle_send_success(
            peer_norm="peer",
            rec=rec3,
            text="adv",
            cmp_name="none",
            pending_by_peer=pending3,
            save_state_fn=lambda state: None,
            append_history_fn=lambda *args: hist3.append(args),
            ui_emit_fn=lambda kind, payload: emits3.append((kind, payload)),
            ts_local_fn=lambda: "TS",
            proto_version=3,
        )
        self.assertEqual(pending3, {})
        self.assertEqual(hist3[0][0], "send")


if __name__ == "__main__":
    unittest.main()
