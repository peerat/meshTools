import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from meshtalk.envelope_v3 import (
    ENVELOPE_V3_TYPE_DATA,
    ENVELOPE_V3_VERSION,
    pack_envelope_v3,
    try_unpack_envelope_v3,
)


class EnvelopeV3Tests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        aes = AESGCM(b"\x11" * 32)
        msg_id = b"12345678"
        payload = b"hello-v3"
        wire = pack_envelope_v3(msg_id, aes, payload)
        self.assertEqual(wire[0], ENVELOPE_V3_VERSION)
        self.assertEqual(wire[1], ENVELOPE_V3_TYPE_DATA)
        status, got_id, got_pt = try_unpack_envelope_v3(wire, aes)
        self.assertEqual(status, "ok")
        self.assertEqual(got_id, msg_id)
        self.assertEqual(got_pt, payload)

    def test_rejects_wrong_version(self) -> None:
        aes = AESGCM(b"\x11" * 32)
        wire = bytearray(pack_envelope_v3(b"12345678", aes, b"hello-v3"))
        wire[0] = 99
        status, got_id, got_pt = try_unpack_envelope_v3(bytes(wire), aes)
        self.assertEqual(status, "nope")
        self.assertIsNone(got_id)
        self.assertIsNone(got_pt)

    def test_rejects_wrong_type(self) -> None:
        aes = AESGCM(b"\x11" * 32)
        wire = bytearray(pack_envelope_v3(b"12345678", aes, b"hello-v3"))
        wire[1] = 99
        status, got_id, got_pt = try_unpack_envelope_v3(bytes(wire), aes)
        self.assertEqual(status, "nope")
        self.assertIsNone(got_id)
        self.assertIsNone(got_pt)

    def test_rejects_truncated_payload(self) -> None:
        aes = AESGCM(b"\x11" * 32)
        wire = pack_envelope_v3(b"12345678", aes, b"hello-v3")
        status, got_id, got_pt = try_unpack_envelope_v3(wire[:-1], aes)
        self.assertEqual(status, "decrypt_fail")
        self.assertEqual(got_id, b"12345678")
        self.assertIsNone(got_pt)

    def test_decrypt_fail_on_tamper(self) -> None:
        aes = AESGCM(b"\x11" * 32)
        wire = bytearray(pack_envelope_v3(b"12345678", aes, b"hello-v3"))
        wire[-1] ^= 0x01
        status, got_id, got_pt = try_unpack_envelope_v3(bytes(wire), aes)
        self.assertEqual(status, "decrypt_fail")
        self.assertEqual(got_id, b"12345678")
        self.assertIsNone(got_pt)


if __name__ == "__main__":
    unittest.main()
