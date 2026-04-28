import unittest

from meshtalk.ui_effects import handle_recv_plain_ui, handle_trace_done_ui


class UiEffectsTests(unittest.TestCase):
    def test_handle_recv_plain_ui(self):
        calls = {"update": [], "chat": [], "hist": [], "log": []}

        ok = handle_recv_plain_ui(
            peer_norm="peer1",
            text_plain="hello world",
            msg_id_plain="m1",
            dialog_id_plain="peer1",
            chat_history={},
            history_has_msg=lambda history, dialog_id, msg_id: False,
            update_peer_meta=lambda peer: calls["update"].append(peer),
            chat_line=lambda *args, **kwargs: calls["chat"].append((args, kwargs)),
            append_history=lambda *args, **kwargs: calls["hist"].append((args, kwargs)),
            log_line=lambda text, level: calls["log"].append((text, level)),
            format_plain_transport_meta=lambda **kwargs: f"meta:{kwargs['received_at_ts']}",
            now_ts=10.0,
            ts_local=lambda: "TS",
        )
        self.assertTrue(ok)
        self.assertEqual(calls["update"], ["peer1"])
        self.assertEqual(len(calls["chat"]), 1)
        self.assertEqual(len(calls["hist"]), 1)
        self.assertEqual(len(calls["log"]), 1)

    def test_handle_trace_done_ui(self):
        chat_history = {
            "peer1": [
                {"msg_id": "t1", "logged": False},
                {"msg_id": "t1:resp", "logged": False},
            ]
        }
        calls = {"chat": [], "hist": []}
        ok = handle_trace_done_ui(
            peer_norm="peer1",
            trace_id="t1",
            meta_data={"attempts": 2, "forward_hops": 3, "ack_hops": 4, "done": True},
            resp_text="route text",
            chat_history=chat_history,
            history_has_msg=lambda history, dialog_id, msg_id: False,
            format_meta=lambda *args, **kwargs: "meta",
            chat_line=lambda *args, **kwargs: calls["chat"].append((args, kwargs)),
            append_history=lambda *args, **kwargs: calls["hist"].append((args, kwargs)),
            tr=lambda key: "Trace request" if key == "trace_request" else key,
            as_optional_float=lambda value: float(value) if value is not None else None,
            now_ts=20.0,
        )
        self.assertTrue(ok)
        self.assertEqual(len(calls["chat"]), 2)
        self.assertEqual(len(calls["hist"]), 2)
        self.assertTrue(chat_history["peer1"][0]["logged"])
        self.assertTrue(chat_history["peer1"][1]["logged"])


if __name__ == "__main__":
    unittest.main()
