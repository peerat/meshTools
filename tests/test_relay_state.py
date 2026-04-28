import unittest

from meshtalk.relay_state import RelayState


class RelayStateTests(unittest.TestCase):
    def test_learn_token_prefers_better_neighbor(self) -> None:
        rs = RelayState()
        rs.update_neighbor("peer_a", delivery_ema=0.95, rtt_ema=1.0, queue_depth=0, snr_ema=8.0)
        rs.update_neighbor("peer_b", delivery_ema=0.55, rtt_ema=8.0, queue_depth=4, snr_ema=1.0)
        token = b"ABCDEFGH"
        upd1 = rs.learn_token(token, "peer_b", advertised_score=0.0)
        upd2 = rs.learn_token(token, "peer_a", advertised_score=0.0)
        self.assertTrue(upd1["changed"])
        self.assertTrue(upd2["changed"])
        self.assertEqual(upd2["best_via"], "peer_a")
        selected = rs.choose_forward_peers(token, exclude_peer="", max_candidates=2)
        self.assertEqual(selected[0], "peer_a")
        self.assertIn("peer_b", selected)

    def test_should_forward_deduplicates_and_respects_ttl(self) -> None:
        rs = RelayState()
        rs.update_neighbor("peer_a", delivery_ema=0.9)
        rs.learn_token(b"ABCDEFGH", "peer_a", advertised_score=0.0)
        msg_id = b"12345678"
        should_fwd, peers = rs.should_forward(
            msg_id=msg_id,
            from_peer="origin",
            ttl=3,
            relay_token=b"ABCDEFGH",
            max_candidates=1,
        )
        self.assertTrue(should_fwd)
        self.assertEqual(peers, ["peer_a"])
        should_fwd2, peers2 = rs.should_forward(
            msg_id=msg_id,
            from_peer="origin",
            ttl=3,
            relay_token=b"ABCDEFGH",
            max_candidates=1,
        )
        self.assertFalse(should_fwd2)
        self.assertEqual(peers2, [])
        should_fwd3, peers3 = rs.should_forward(
            msg_id=b"ABCDEFG1",
            from_peer="origin",
            ttl=1,
            relay_token=b"ABCDEFGH",
            max_candidates=1,
        )
        self.assertFalse(should_fwd3)
        self.assertEqual(peers3, [])

    def test_dedup_is_scoped_by_relay_token(self) -> None:
        rs = RelayState()
        rs.update_neighbor("peer_a", delivery_ema=0.9)
        rs.update_neighbor("peer_b", delivery_ema=0.9)
        rs.learn_token(b"ABCDEFGH", "peer_a", advertised_score=0.0)
        rs.learn_token(b"HGFEDCBA", "peer_b", advertised_score=0.0)
        msg_id = b"12345678"
        should_fwd1, peers1 = rs.should_forward(
            msg_id=msg_id,
            from_peer="origin",
            ttl=3,
            relay_token=b"ABCDEFGH",
            max_candidates=1,
        )
        should_fwd2, peers2 = rs.should_forward(
            msg_id=msg_id,
            from_peer="origin",
            ttl=3,
            relay_token=b"HGFEDCBA",
            max_candidates=1,
        )
        self.assertTrue(should_fwd1)
        self.assertEqual(peers1, ["peer_a"])
        self.assertTrue(should_fwd2)
        self.assertEqual(peers2, ["peer_b"])


if __name__ == "__main__":
    unittest.main()
