import unittest

from meshtalk.ui_helpers import build_gui_config_payload, split_chat_timestamp, strip_parenthesized_prefix


class _Args:
    port = "/dev/ttyUSB0"
    channel = 0
    retry_seconds = 30
    max_seconds = 86400
    max_bytes = 200
    rate_seconds = 15
    parallel_sends = 1


class UiHelpersTests(unittest.TestCase):
    def test_split_and_strip_chat_text(self) -> None:
        ts, msg = split_chat_timestamp("12:34 hello")
        self.assertEqual(ts, "12:34")
        self.assertEqual(msg, "hello")
        ts2, msg2 = split_chat_timestamp("hello", fallback_ts="00:00")
        self.assertEqual((ts2, msg2), ("00:00", "hello"))
        self.assertEqual(strip_parenthesized_prefix("(1/2) hello"), "hello")
        self.assertEqual(strip_parenthesized_prefix("hello"), "hello")

    def test_build_gui_config_payload(self) -> None:
        payload = build_gui_config_payload(
            current_lang="ru",
            verbose_log=True,
            runtime_log_file=False,
            auto_pacing=True,
            pinned_dialogs={"b", "a"},
            hidden_contacts={"z"},
            groups={"g": {"2", "1"}},
            cfg={},
            args=_Args(),
            data_port_label="PRIVATE_APP",
            normalize_activity_controller_model_fn=lambda v: str(v),
            activity_controller_default="trickle",
            msg_retry_active_window_seconds=300.0,
            msg_retry_muted_interval_seconds=600.0,
            msg_retry_probe_window_seconds=120.0,
            peer_responsive_grace_seconds=30.0,
            retry_backoff_max_seconds=900.0,
            retry_jitter_ratio=0.1,
            discovery_send=True,
            discovery_reply=False,
            clear_pending_on_switch=True,
            contacts_visibility="online",
            current_theme="ubuntu_style",
            peer_meta={"x": {}},
        )
        self.assertEqual(payload["lang"], "ru")
        self.assertEqual(payload["pinned_dialogs"], ["a", "b"])
        self.assertEqual(payload["groups"]["g"], ["1", "2"])
        self.assertEqual(payload["mesh_packet_portnum"], "PRIVATE_APP")
        self.assertFalse(payload["discovery_enabled"])


if __name__ == "__main__":
    unittest.main()
