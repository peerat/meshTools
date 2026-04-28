import unittest

from meshtalk.ui_events import (
    as_optional_float,
    parse_groups_config,
    parse_peer_meta_records,
    parse_queued_payload,
    parse_recv_payload,
    parse_recv_plain_payload,
    parse_trace_update_payload,
    update_outgoing_ack_tracker,
)


class UiEventsTests(unittest.TestCase):
    def test_as_optional_float(self):
        self.assertEqual(as_optional_float("1.25"), 1.25)
        self.assertIsNone(as_optional_float(None))
        self.assertIsNone(as_optional_float("bad"))

    def test_parse_trace_update_payload(self):
        self.assertEqual(
            parse_trace_update_payload(("peer", "trace", "2.5")),
            ("peer", "trace", 2.5),
        )
        self.assertIsNone(parse_trace_update_payload(("peer", "", 1)))

    def test_parse_recv_payload(self):
        parsed = parse_recv_payload(("a", "txt", 1.0, 0.5, "gid", 1, 2, 3, "chunk", 1, "bz2", "mc_bz2", True))
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["from_id"], "a")
        self.assertEqual(parsed["compression_flag"], 1)
        self.assertTrue(parsed["compact_wire"])

    def test_parse_recv_plain_and_queue(self):
        self.assertEqual(
            parse_recv_plain_payload(("peer", "hello", "id1", "group:Primary")),
            ("peer", "hello", "id1", "group:Primary"),
        )
        self.assertEqual(
            parse_queued_payload(("peer", "gid", "10", "2", "mc_bz2")),
            ("peer", "gid", 10, 2, "mc_bz2"),
        )

    def test_update_outgoing_ack_tracker(self):
        store = {}
        first = update_outgoing_ack_tracker(store, ("peer", "gid", 0.5, 2, 2, 3, 4))
        self.assertEqual(first[-1], (1, 2))
        second = update_outgoing_ack_tracker(store, ("peer", "gid", 0.5, 4, 2, 5, 6))
        self.assertEqual(second[-1], (2, 2))
        self.assertNotIn("gid", store)
        self.assertAlmostEqual(second[3], 3.0)
        self.assertAlmostEqual(second[4], 4.0)
        self.assertAlmostEqual(second[5], 5.0)

    def test_parse_peer_meta_and_groups(self):
        peer_meta = parse_peer_meta_records(
            {
                "A": {"last_seen_ts": 1, "device_seen_ts": 2, "key_confirmed_ts": 3},
                "B": {"last_seen_ts": 0},
                "C": "bad",
            },
            lambda x: x.lower(),
        )
        self.assertEqual(peer_meta["a"]["last_seen_ts"], 1.0)
        self.assertEqual(peer_meta["a"]["device_seen_ts"], 2.0)
        self.assertEqual(peer_meta["a"]["key_confirmed_ts"], 3.0)
        self.assertNotIn("b", peer_meta)
        groups = parse_groups_config({"g1": ["a", "b"], "g2": "bad"})
        self.assertEqual(groups, {"g1": {"a", "b"}})


if __name__ == "__main__":
    unittest.main()
