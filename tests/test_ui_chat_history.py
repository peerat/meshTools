import unittest

from meshtalk.ui_chat_history import history_has_msg, update_outgoing_delivery_state, update_outgoing_failed_state


class UiChatHistoryTests(unittest.TestCase):
    def test_history_has_msg(self) -> None:
        history = {"peer": [{"msg_id": "a"}, {"msg_id": "b"}]}
        self.assertTrue(history_has_msg(history, "peer", "a"))
        self.assertFalse(history_has_msg(history, "peer", "c"))

    def test_update_outgoing_delivery_and_failed(self) -> None:
        calls = []
        history = {
            "peer": [
                {
                    "dir": "out",
                    "msg_id": "m1",
                    "text": "12:34 (1/2) hello",
                    "meta_data": {
                        "sent_at_ts": 100.0,
                        "compression_name": "bz2",
                        "compression_eff_pct": 42.0,
                        "compression_norm": "TOKENS",
                    },
                }
            ]
        }

        def _format_meta(*args, **kwargs):
            return f"meta:{kwargs.get('status') or 'ok'}"

        updated = update_outgoing_delivery_state(
            chat_history=history,
            dialog_id="peer",
            msg_id="m1",
            delivery=1.0,
            attempts=2.0,
            forward_hops=1.0,
            ack_hops=2.0,
            packets=(2, 2),
            format_meta_fn=_format_meta,
            normalize_compression_name_fn=lambda v: v.upper() if v else None,
            update_dialog_fn=lambda dialog_id, text, recv: calls.append(("dialog", dialog_id, text, recv)),
            render_chat_fn=lambda dialog_id: calls.append(("render", dialog_id)),
            refresh_list_fn=lambda: calls.append(("refresh",)),
            append_history_fn=lambda *args, **kwargs: calls.append(("append", args[0], args[1], args[2])),
            current_dialog="peer",
        )
        self.assertTrue(updated)
        self.assertEqual(history["peer"][0]["meta"], "meta:ok")
        self.assertTrue(history["peer"][0].get("logged"))
        self.assertEqual(calls[0][0], "dialog")
        self.assertEqual(calls[1][0], "render")
        self.assertEqual(calls[2][0], "append")

        calls.clear()
        failed = update_outgoing_failed_state(
            chat_history=history,
            dialog_id="peer",
            msg_id="m1",
            reason="timeout",
            attempts=3,
            total=2,
            format_meta_fn=_format_meta,
            normalize_compression_name_fn=lambda v: v.upper() if v else None,
            update_dialog_fn=lambda dialog_id, text, recv: calls.append(("dialog", dialog_id, text, recv)),
            render_chat_fn=lambda dialog_id: calls.append(("render", dialog_id)),
            refresh_list_fn=lambda: calls.append(("refresh",)),
            current_dialog="peer",
        )
        self.assertTrue(failed)
        self.assertEqual(history["peer"][0]["meta"], "meta:timeout")
        self.assertEqual(calls[0][0], "dialog")
        self.assertEqual(calls[1][0], "render")


if __name__ == "__main__":
    unittest.main()
