import unittest

from meshtalk.v3_sender import (
    collect_candidate_peers,
    collect_fast_retry_candidates,
    peer_fast_profile,
    prepare_send_window,
    round_robin_peers,
    send_budget_blocked,
)


class V3SenderTests(unittest.TestCase):
    def test_peer_fast_profile_prefers_peer_override(self) -> None:
        cfg = {
            "activity_fast_retries": 0,
            "activity_fast_retry_min_ms": 350,
            "activity_fast_retry_max_ms": 850,
        }
        peer_meta = {
            "deadbeef": {
                "activity_fast_retries": 2,
                "activity_fast_retry_min_ms": 120,
                "activity_fast_retry_max_ms": 480,
            }
        }
        self.assertEqual(peer_fast_profile(cfg, peer_meta, "deadbeef"), (2, 120, 480))
        self.assertEqual(peer_fast_profile(cfg, peer_meta, "missing"), (0, 350, 850))

    def test_collect_fast_retry_candidates_sorted_by_created(self) -> None:
        pending_by_peer = {
            "a": {
                "1": {"fast_left": 1, "fast_next_ts": 5.0, "created": 20.0},
                "2": {"fast_left": 0, "fast_next_ts": 1.0, "created": 1.0},
            },
            "b": {
                "3": {"fast_left": 2, "fast_next_ts": 4.0, "created": 10.0},
            },
        }
        rows = collect_fast_retry_candidates(pending_by_peer, now=6.0)
        self.assertEqual([peer for peer, _ in rows], ["b", "a"])
        self.assertEqual([float(rec["created"]) for _, rec in rows], [10.0, 20.0])

    def test_send_window_and_round_robin_helpers(self) -> None:
        start, count, last_tx = prepare_send_window(
            now=10.0,
            rate_s=5.0,
            send_window_start_ts=1.0,
            send_window_count=3,
            send_window_last_tx_ts=9.0,
        )
        self.assertEqual((start, count, last_tx), (10.0, 0, 0.0))
        self.assertTrue(
            send_budget_blocked(
                now=10.0,
                rate_s=5.0,
                send_window_count=2,
                parallel=2,
                intra_gap_s=0.0,
                send_window_last_tx_ts=0.0,
            )
        )
        self.assertTrue(
            send_budget_blocked(
                now=10.0,
                rate_s=0.0,
                send_window_count=1,
                parallel=2,
                intra_gap_s=2.0,
                send_window_last_tx_ts=9.0,
            )
        )
        peers = collect_candidate_peers(["b", "a"], ["c", "a"])
        self.assertEqual(peers, ["a", "b", "c"])
        rr_start, rr_rows = round_robin_peers(["a", "b", "c"], 1)
        self.assertEqual(rr_start, 1)
        self.assertEqual([peer for _, peer in rr_rows], ["b", "c", "a"])


if __name__ == "__main__":
    unittest.main()
