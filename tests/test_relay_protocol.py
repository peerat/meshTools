import unittest

from meshtalk.relay_protocol import (
    RELAY_HEADER_LEN,
    RELAY_MAGIC,
    RELAY_VERSION,
    RELAY_FLAG_LOW_NOISE,
    RELAY_TYPE_CAPS_REQ,
    RELAY_TYPE_DATA,
    RELAY_TYPE_END_ACK,
    RELAY_TYPE_HOP_ACK,
    build_caps_req_frame,
    build_data_frame,
    build_hop_ack_frame,
    build_end_ack_frame,
    current_epoch_slot,
    decrement_ttl,
    derive_relay_token,
    generate_msg_id,
    parse_frame,
    serialize_frame,
    split_payload_chunks,
)


class RelayProtocolTests(unittest.TestCase):
    def test_relay_frame_roundtrip(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_000)
        msg_id = generate_msg_id()
        relay_token = derive_relay_token("deadbeef", epoch)
        return_token = derive_relay_token("cafebabe", epoch)
        payload = b"A" * 64
        frame_raw = build_data_frame(
            msg_id=msg_id,
            relay_token=relay_token,
            return_token=return_token,
            body=payload,
            ttl=4,
            flags=RELAY_FLAG_LOW_NOISE,
            frag_index=2,
            frag_total=3,
            epoch_slot=epoch,
        )
        frame = parse_frame(frame_raw)
        self.assertIsNotNone(frame)
        assert frame is not None
        self.assertEqual(frame.frame_type, RELAY_TYPE_DATA)
        self.assertEqual(frame.flags, RELAY_FLAG_LOW_NOISE)
        self.assertEqual(frame.ttl, 4)
        self.assertEqual(frame.frag_index, 2)
        self.assertEqual(frame.frag_total, 3)
        self.assertEqual(frame.epoch_slot, epoch)
        self.assertEqual(frame.msg_id, msg_id)
        self.assertEqual(frame.relay_token, relay_token)
        self.assertEqual(frame.return_token, return_token)
        self.assertEqual(frame.body, payload)
        self.assertEqual(serialize_frame(frame), frame_raw)

    def test_ttl_decrement(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_100)
        frame = parse_frame(
            build_end_ack_frame(
                msg_id=b"12345678",
                return_token=derive_relay_token("feedface", epoch),
                ttl=4,
                epoch_slot=epoch,
            )
        )
        self.assertIsNotNone(frame)
        assert frame is not None
        self.assertEqual(frame.frame_type, RELAY_TYPE_END_ACK)
        dec = decrement_ttl(frame)
        self.assertEqual(dec.ttl, 3)

    def test_ttl_decrement_floors_at_zero(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_100)
        frame = parse_frame(
            build_end_ack_frame(
                msg_id=b"12345678",
                return_token=derive_relay_token("feedface", epoch),
                ttl=0,
                epoch_slot=epoch,
            )
        )
        self.assertIsNotNone(frame)
        assert frame is not None
        dec = decrement_ttl(frame)
        self.assertEqual(dec.ttl, 0)

    def test_hop_ack_carries_fragment_index(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_101)
        frame = parse_frame(
            build_hop_ack_frame(
                msg_id=b"12345678",
                return_token=derive_relay_token("feedface", epoch),
                frag_index=7,
                epoch_slot=epoch,
            )
        )
        self.assertIsNotNone(frame)
        assert frame is not None
        self.assertEqual(frame.frame_type, RELAY_TYPE_HOP_ACK)
        self.assertEqual(frame.body, b"\x00\x07")

    def test_caps_req_roundtrip(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_102)
        frame = parse_frame(build_caps_req_frame(epoch_slot=epoch))
        self.assertIsNotNone(frame)
        assert frame is not None
        self.assertEqual(frame.frame_type, RELAY_TYPE_CAPS_REQ)
        self.assertEqual(frame.ttl, 1)
        self.assertEqual(frame.body, b"")

    def test_split_payload_chunks(self) -> None:
        payload = b"0123456789ABCDEF"
        parts = split_payload_chunks(payload, 5)
        self.assertEqual(parts, [b"01234", b"56789", b"ABCDE", b"F"])

    def test_parse_rejects_short_payload(self) -> None:
        self.assertIsNone(parse_frame(b"\x00" * (RELAY_HEADER_LEN - 1)))

    def test_parse_rejects_bad_magic(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_200)
        frame_raw = bytearray(
            build_data_frame(
                msg_id=b"12345678",
                relay_token=derive_relay_token("deadbeef", epoch),
                return_token=derive_relay_token("cafebabe", epoch),
                body=b"x",
                epoch_slot=epoch,
            )
        )
        frame_raw[:3] = b"BAD"
        self.assertIsNone(parse_frame(bytes(frame_raw)))

    def test_parse_rejects_bad_version(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_201)
        frame_raw = bytearray(
            build_data_frame(
                msg_id=b"12345678",
                relay_token=derive_relay_token("deadbeef", epoch),
                return_token=derive_relay_token("cafebabe", epoch),
                body=b"x",
                epoch_slot=epoch,
            )
        )
        frame_raw[3] = RELAY_VERSION + 1
        self.assertIsNone(parse_frame(bytes(frame_raw)))

    def test_parse_rejects_unknown_type(self) -> None:
        epoch = current_epoch_slot(now=1_700_000_202)
        frame_raw = bytearray(
            build_data_frame(
                msg_id=b"12345678",
                relay_token=derive_relay_token("deadbeef", epoch),
                return_token=derive_relay_token("cafebabe", epoch),
                body=b"x",
                epoch_slot=epoch,
            )
        )
        frame_raw[4] = 255
        self.assertIsNone(parse_frame(bytes(frame_raw)))


if __name__ == "__main__":
    unittest.main()
