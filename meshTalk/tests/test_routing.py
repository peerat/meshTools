import unittest

from meshtalk.routing import RoutingController


class TestRoutingController(unittest.TestCase):
    def test_cold_start_prefers_plain_text_on_tie(self):
        ctl = RoutingController({})
        d = ctl.select_unicast_route("coldpeer", ["meshTalk", "meshtastic_text"], now=1000.0)
        self.assertEqual(d.route_id, "meshtastic_text")

    def test_select_prefers_better_delivery(self):
        ctl = RoutingController({})
        peer = "a1b2c3d4"
        # meshTalk: clean success.
        ctl.observe_tx_result(peer, "meshTalk", now=1000.0, success=True, attempts=1, rtt_s=1.2, hops=1)
        ctl.observe_tx_result(peer, "meshTalk", now=1001.0, success=True, attempts=1, rtt_s=1.0, hops=1)
        # text: repeated failures/timeouts.
        ctl.observe_tx_result(peer, "meshtastic_text", now=1000.0, success=False, timeout=True, attempts=2, rtt_s=None, hops=None)
        ctl.observe_tx_result(peer, "meshtastic_text", now=1001.0, success=False, timeout=True, attempts=2, rtt_s=None, hops=None)
        d = ctl.select_unicast_route(peer, ["meshTalk", "meshtastic_text"], queue_depth=0, now=1002.0)
        self.assertEqual(d.route_id, "meshTalk")

    def test_hysteresis_holds_route(self):
        cfg = {
            "routing_hysteresis_rel": 0.50,
            "routing_hysteresis_abs": 0.20,
            "routing_sticky_hold_seconds": 0.0,
            "routing_min_samples": 1,
        }
        ctl = RoutingController(cfg)
        peer = "11223344"
        ctl.observe_tx_result(peer, "meshTalk", now=1000.0, success=True, attempts=1, rtt_s=2.0, hops=2)
        ctl.observe_tx_result(peer, "meshtastic_text", now=1000.0, success=True, attempts=1, rtt_s=1.8, hops=2)
        d1 = ctl.select_unicast_route(peer, ["meshTalk", "meshtastic_text"], now=1001.0)
        # slightly improve text; should still hold old route due to high hysteresis
        ctl.observe_tx_result(peer, "meshtastic_text", now=1002.0, success=True, attempts=1, rtt_s=1.7, hops=2)
        d2 = ctl.select_unicast_route(peer, ["meshTalk", "meshtastic_text"], now=1003.0)
        self.assertEqual(d2.route_id, d1.route_id)

    def test_fast_failover_on_bad_timeout_ema(self):
        cfg = {
            "routing_hysteresis_rel": 0.90,
            "routing_hysteresis_abs": 0.90,
            "routing_sticky_hold_seconds": 9999.0,  # would block switching without failover
            "routing_failover_timeout_ema": 0.30,
            "routing_min_samples": 1,
        }
        ctl = RoutingController(cfg)
        peer = "cafebabe"
        # establish meshTalk as selected
        ctl.observe_tx_result(peer, "meshTalk", now=1000.0, success=True, attempts=1, rtt_s=1.0, hops=1)
        ctl.observe_tx_result(peer, "meshtastic_text", now=1000.0, success=True, attempts=1, rtt_s=1.0, hops=1)
        ctl.select_unicast_route(peer, ["meshTalk"], now=1000.5)
        d1 = ctl.select_unicast_route(peer, ["meshTalk", "meshtastic_text"], now=1001.0)
        self.assertEqual(d1.route_id, "meshTalk")
        # sharp degradation on meshTalk
        ctl.observe_tx_result(peer, "meshTalk", now=1002.0, success=False, timeout=True, attempts=3, rtt_s=None, hops=None)
        ctl.observe_tx_result(peer, "meshTalk", now=1003.0, success=False, timeout=True, attempts=3, rtt_s=None, hops=None)
        d2 = ctl.select_unicast_route(peer, ["meshTalk", "meshtastic_text"], now=1004.0)
        self.assertEqual(d2.reason, "fast_failover")
        self.assertEqual(d2.route_id, "meshtastic_text")

    def test_group_target_cap(self):
        ctl = RoutingController({"routing_group_fanout_cap": 2})
        peers = ["p1", "p2", "p3"]
        for i, p in enumerate(peers):
            ctl.observe_tx_result(p, "meshTalk", now=1000.0 + i, success=True, attempts=1, rtt_s=1.0 + i, hops=1 + i)
        out = ctl.choose_group_targets(peers, now=1005.0)
        self.assertLessEqual(len(out), 2)

    def test_control_bucket(self):
        ctl = RoutingController({"routing_control_rate_per_second": 1.0, "routing_control_burst": 1.0, "routing_control_min_interval_seconds": 0.0})
        self.assertTrue(ctl.allow_control("key", now=1000.0))
        self.assertFalse(ctl.allow_control("key", now=1000.01))
        self.assertTrue(ctl.allow_control("key", now=1001.5))

    def test_rx_telemetry_increases_samples(self):
        ctl = RoutingController({"routing_min_samples": 6})
        peer = "telepeer"
        ctl.observe_rx_telemetry(peer, "meshTalk", now=1000.0, snr_db=6.0, hops=1)
        stats = ctl.export_peer_stats(peer)
        self.assertEqual(stats["routes"]["meshTalk"]["samples"], 1)

    def test_local_send_attempt_does_not_count_as_delivery(self):
        ctl = RoutingController({})
        peer = "plainpeer"
        ctl.observe_local_send_attempt(peer, "meshtastic_text", now=1000.0)
        stats = ctl.export_peer_stats(peer)
        route = stats["routes"]["meshtastic_text"]
        self.assertEqual(route["samples"], 0)
        self.assertAlmostEqual(route["delivery_ema"], 0.50, places=3)


if __name__ == "__main__":
    unittest.main()
