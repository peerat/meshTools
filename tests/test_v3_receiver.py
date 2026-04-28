import unittest
import time

from meshtalk.mt2_frames import parse_caps_frame
from meshtalk.relay_protocol import build_data_frame, build_hop_ack_frame, current_epoch_slot, derive_relay_token, parse_frame
from meshtalk.v3_receiver import (
    compute_end_ack_forward,
    decode_completed_relay_text,
    detect_legacy_control_drop,
    ingest_relay_fragment,
    learn_relay_neighbor,
    parse_token_adv_score,
    update_caps_from_body,
)
from meshtalk.relay_state import RelayState


class _PeerState:
    def __init__(self) -> None:
        self.caps = {}
        self.caps_recv_ts = 0.0
        self.peer_wire_versions = set()
        self.peer_msg_versions = set()
        self.peer_mc_versions = set()
        self.compression_modes = set()
        self.aad_type_bound = False


class V3ReceiverTests(unittest.TestCase):
    def test_detect_legacy_control_drop(self) -> None:
        self.assertEqual(
            detect_legacy_control_drop(
                b"CPR",
                peer_norm="deadbeef",
                from_id="!deadbeef",
                caps_req_prefix=b"CPR",
                caps_ctrl_prefix=b"CPS",
                rekey1_prefix=b"RK1",
                rekey2_prefix=b"RK2",
                rekey3_prefix=b"RK3",
            ),
            "caps_req",
        )
        self.assertEqual(
            detect_legacy_control_drop(
                b"RK3ABCD",
                peer_norm="deadbeef",
                from_id="!deadbeef",
                caps_req_prefix=b"CPR",
                caps_ctrl_prefix=b"CPS",
                rekey1_prefix=b"RK1",
                rekey2_prefix=b"RK2",
                rekey3_prefix=b"RK3",
            ),
            "rk3",
        )

    def test_parse_token_adv_and_learn_neighbor(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_400)
        token = derive_relay_token("deadbeef", epoch)
        frame = parse_frame(build_hop_ack_frame(msg_id=b"ABCDEFGH", return_token=token, frag_index=1, epoch_slot=epoch))
        self.assertIsNotNone(frame)
        assert frame is not None
        state = RelayState()
        learn_relay_neighbor(state, "deadbeef", frame, relay_token_for_peer=lambda peer, slot: derive_relay_token(peer, slot), now=10.0)
        self.assertIn("deadbeef", state.neighbors)

    def test_update_caps_from_body(self) -> None:
        st = _PeerState()
        caps = update_caps_from_body(
            st,
            b"CP1|wire=2,3|msg=1,2|mc=1,9|aad=1",
            parse_caps_frame=parse_caps_frame,
            parse_caps_versions=lambda raw: [int(x) for x in str(raw or "").split(",") if str(x).strip()],
            supported_mc_modes=[1, 9],
            now=22.0,
        )
        self.assertEqual(caps["wire"], "2,3")
        self.assertEqual(st.peer_wire_versions, {2, 3})
        self.assertEqual(st.peer_msg_versions, {1, 2})
        self.assertEqual(st.compression_modes, {1, 9})
        self.assertTrue(st.aad_type_bound)

    def test_ingest_and_decode_relay_text(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_402)
        token = derive_relay_token("deadbeef", epoch)
        frame = parse_frame(
            build_data_frame(
                msg_id=b"ABCDEFGH",
                relay_token=token,
                return_token=token,
                body=b"\x00hello",
                ttl=5,
                frag_index=1,
                frag_total=1,
                epoch_slot=epoch,
            )
        )
        self.assertIsNotNone(frame)
        assert frame is not None
        incoming = {}
        rec, ready = ingest_relay_fragment(incoming, "deadbeef", frame)
        self.assertTrue(ready)
        text, compression_v3, msg_blob = decode_completed_relay_text(rec, decompress_text=lambda data: data.decode("utf-8"))
        self.assertEqual(text, "hello")
        self.assertEqual(compression_v3, 0)
        self.assertEqual(msg_blob, b"hello")

    def test_compute_end_ack_forward(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_403)
        token = derive_relay_token("cafebabe", epoch)
        state = RelayState()
        state.learn_token(token, "cafebabe", now=time.time())
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
        next_peers = compute_end_ack_forward(state, frame, "deadbeef")
        self.assertEqual(next_peers, ["cafebabe"])

    def test_parse_token_adv_score(self) -> None:
        class _F:
            body = b"\x03\xe8"
        self.assertEqual(parse_token_adv_score(_F()), 1000)


if __name__ == "__main__":
    unittest.main()
