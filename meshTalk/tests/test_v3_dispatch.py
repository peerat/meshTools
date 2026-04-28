import time
import unittest

from meshtalk.relay_protocol import build_data_frame, build_token_adv_frame, current_epoch_slot, derive_relay_token, parse_frame
from meshtalk.relay_state import RelayState
from meshtalk.v3_dispatch import build_recv_event, plan_ack_frame, plan_data_forward, plan_token_adv_frame


class V3DispatchTests(unittest.TestCase):
    def test_plan_ack_frame(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_500)
        token = derive_relay_token("cafebabe", epoch)
        st = RelayState()
        st.learn_token(token, "cafebabe", now=time.time())
        frame = parse_frame(
            build_data_frame(
                msg_id=b"ABCDEFGH",
                relay_token=token,
                return_token=token,
                body=b"x",
                ttl=3,
                frag_index=1,
                frag_total=1,
                epoch_slot=epoch,
            )
        )
        self.assertIsNotNone(frame)
        assert frame is not None
        plan = plan_ack_frame(st, frame, peer_norm="deadbeef", ack_part=1, token_matches_self=False)
        self.assertEqual(plan["ack_part"], 1)
        self.assertFalse(plan["delivered_local"])
        self.assertEqual(plan["next_peers"], ["cafebabe"])

    def test_plan_token_adv_frame(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_501)
        token = derive_relay_token("cafebabe", epoch)
        st = RelayState()
        st.update_neighbor("deadbeef", now=time.time())
        frame = parse_frame(
            build_token_adv_frame(
                relay_token=token,
                reach_score=1000,
                ttl=3,
                epoch_slot=epoch,
            )
        )
        self.assertIsNotNone(frame)
        assert frame is not None
        plan = plan_token_adv_frame(st, frame, peer_norm="deadbeef", now=time.time())
        self.assertEqual(plan["adv_score"], 1000)
        self.assertIn("deadbeef", st.neighbors)
        self.assertTrue(plan["route_update"]["changed"])
        self.assertEqual(plan["route_update"]["best_via"], "deadbeef")
        self.assertEqual(st.reachability[token][0].hops, 2)

    def test_plan_data_forward_and_recv_event(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_502)
        token = derive_relay_token("cafebabe", epoch)
        st = RelayState()
        st.learn_token(token, "cafebabe", now=time.time())
        frame = parse_frame(
            build_data_frame(
                msg_id=b"ABCDEFGH",
                relay_token=token,
                return_token=token,
                body=b"x",
                ttl=4,
                frag_index=1,
                frag_total=1,
                epoch_slot=epoch,
            )
        )
        self.assertIsNotNone(frame)
        assert frame is not None
        self.assertEqual(plan_data_forward(st, frame, peer_norm="deadbeef"), ["cafebabe"])
        evt = build_recv_event("deadbeef", frame, {"hopStart": 6, "hopLimit": 4}, "hello", 0)
        self.assertIsNotNone(evt)
        assert evt is not None
        self.assertEqual(evt[0], "deadbeef")
        self.assertEqual(evt[1], "hello")
        self.assertEqual(evt[2], 2)
        self.assertEqual(evt[4], "4142434445464748")


if __name__ == "__main__":
    unittest.main()
