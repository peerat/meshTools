import unittest

from meshtalk.routing_sim import (
    render_demo,
    render_transport_route_dot,
    simulate_relay_route_learning,
    simulate_transport_route_progression,
)


class TestRoutingSimulation(unittest.TestCase):
    def test_transport_simulation_shows_failover(self):
        rows = simulate_transport_route_progression()
        self.assertGreaterEqual(len(rows), 4)
        self.assertEqual(rows[0].step, "cold_start")
        self.assertEqual(rows[0].selected, "meshtastic_text")
        self.assertTrue(any(r.reason == "fast_failover" for r in rows))

    def test_relay_simulation_changes_best_peer(self):
        rows = simulate_relay_route_learning()
        self.assertEqual(rows[0].best_via, "peer_b")
        self.assertEqual(rows[1].best_via, "peer_c")
        self.assertEqual(rows[2].best_via, "peer_b")

    def test_render_demo_contains_visualization(self):
        text = render_demo()
        self.assertIn("=== Transport Route Simulation ===", text)
        self.assertIn("=== Transport Route DOT ===", text)
        self.assertIn("=== Relay Route Simulation ===", text)
        self.assertIn("fast_failover", text)
        self.assertIn("peer_c_becomes_best", text)

    def test_dot_render_contains_graphviz(self):
        text = render_transport_route_dot(simulate_transport_route_progression())
        self.assertIn("digraph transport_route_sim", text)
        self.assertIn("fast_failover", text)


if __name__ == "__main__":
    print(render_demo())
    unittest.main()
