import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from meshtalk.envelope_v3 import pack_envelope_v3, try_unpack_envelope_v3
from meshtalk.relay_protocol import (
    RELAY_TYPE_DATA,
    RELAY_TYPE_END_ACK,
    RELAY_TYPE_HOP_ACK,
    build_data_frame,
    build_end_ack_frame,
    build_hop_ack_frame,
    current_epoch_slot,
    derive_relay_token,
    parse_frame,
)
from meshtalk.relay_state import RelayState


class V3FlowTests(unittest.TestCase):
    def test_end_to_end_data_and_ack_flow(self) -> None:
        aes = AESGCM(b"\x22" * 32)
        epoch = current_epoch_slot(now=1_700_000_200)

        sender = "aaaabbbb"
        relay = "ccccdddd"
        receiver = "eeeeffff"

        relay_token = derive_relay_token(receiver, epoch)
        return_token = derive_relay_token(sender, epoch)
        msg_id = b"ABCDEFGH"
        data_plain = bytes([0]) + b"hello"

        wire = pack_envelope_v3(
            b"12345678",
            aes,
            build_data_frame(
                msg_id=msg_id,
                relay_token=relay_token,
                return_token=return_token,
                body=data_plain,
                ttl=5,
                frag_index=1,
                frag_total=1,
                epoch_slot=epoch,
            ),
        )
        status, _, inner = try_unpack_envelope_v3(wire, aes)
        self.assertEqual(status, "ok")
        frame = parse_frame(inner)
        self.assertIsNotNone(frame)
        assert frame is not None
        self.assertEqual(frame.frame_type, RELAY_TYPE_DATA)
        self.assertEqual(frame.relay_token, relay_token)

        hop_ack = parse_frame(
            build_hop_ack_frame(
                msg_id=frame.msg_id,
                return_token=frame.return_token,
                frag_index=frame.frag_index,
                epoch_slot=frame.epoch_slot,
            )
        )
        self.assertIsNotNone(hop_ack)
        assert hop_ack is not None
        self.assertEqual(hop_ack.frame_type, RELAY_TYPE_HOP_ACK)
        self.assertEqual(hop_ack.body, b"\x00\x01")

        end_ack = parse_frame(
            build_end_ack_frame(
                msg_id=frame.msg_id,
                return_token=frame.return_token,
                ttl=5,
                epoch_slot=frame.epoch_slot,
            )
        )
        self.assertIsNotNone(end_ack)
        assert end_ack is not None
        self.assertEqual(end_ack.frame_type, RELAY_TYPE_END_ACK)
        self.assertEqual(end_ack.return_token, return_token)

        rs = RelayState()
        rs.update_neighbor(relay, delivery_ema=0.9)
        rs.learn_token(return_token, relay, advertised_score=0.0)
        should_fwd, peers = rs.should_forward(
            msg_id=b"\xEE" + msg_id[1:8],
            from_peer=receiver,
            ttl=end_ack.ttl,
            relay_token=end_ack.return_token,
            max_candidates=1,
        )
        self.assertTrue(should_fwd)
        self.assertEqual(peers, [relay])


if __name__ == "__main__":
    unittest.main()
