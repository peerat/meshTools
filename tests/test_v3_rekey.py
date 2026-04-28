import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from meshtalk.relay_protocol import build_rekey1_frame, build_rekey2_frame, build_rekey3_frame, current_epoch_slot, parse_frame
from meshtalk.v3_rekey import handle_rekey1, handle_rekey2, handle_rekey3


class _PeerState:
    def __init__(self) -> None:
        self.aes = AESGCM(b"\x11" * 32)
        self.prev_aes = None
        self.prev_aes_until_ts = 0.0
        self.last_rekey_ts = 0.0
        self.rekey_sent_msgs = 9
        self.rekey_inflight = False
        self.rekey_priv = None
        self.rekey_id = b""
        self.rekey_attempts = 3
        self.rekey_next_retry_ts = 7.0
        self.rekey_candidate_id = b""
        self.rekey_candidate_pub = b""
        self.rekey_candidate_aes = None
        self.rekey_candidate_ts = 0.0


def _derive(_peer: str, shared: bytes):
    return AESGCM((shared[:32]).ljust(32, b"\x22"))


class V3RekeyTests(unittest.TestCase):
    def test_handle_rekey1_sets_candidate_and_returns_rk2(self) -> None:
        st = _PeerState()
        epoch = current_epoch_slot(now=1_700_000_600)
        peer_priv = x25519.X25519PrivateKey.generate()
        peer_pub = peer_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        frame = parse_frame(build_rekey1_frame(rid=b"ABCD", epub=peer_pub, epoch_slot=epoch))
        self.assertIsNotNone(frame)
        assert frame is not None
        out = handle_rekey1(st, "deadbeef", frame, now=12.0, derive_aes_fn=_derive)
        self.assertIsNotNone(out["response_frame"])
        self.assertIsNone(out["response_aes_override"])
        self.assertEqual(st.rekey_candidate_id, b"ABCD")
        self.assertTrue(st.rekey_candidate_pub)
        self.assertIsNotNone(st.rekey_candidate_aes)

    def test_handle_rekey2_switches_initiator_key(self) -> None:
        st = _PeerState()
        epoch = current_epoch_slot(now=1_700_000_601)
        local_priv = x25519.X25519PrivateKey.generate()
        peer_priv = x25519.X25519PrivateKey.generate()
        peer_pub = peer_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        st.rekey_inflight = True
        st.rekey_priv = local_priv
        st.rekey_id = b"ABCD"
        frame = parse_frame(build_rekey2_frame(rid=b"ABCD", repub=peer_pub, epoch_slot=epoch))
        self.assertIsNotNone(frame)
        assert frame is not None
        out = handle_rekey2(st, "deadbeef", frame, now=14.0, derive_aes_fn=_derive, prev_key_grace_seconds=300.0)
        self.assertIsNotNone(out["response_frame"])
        self.assertIsNotNone(out["response_aes_override"])
        self.assertFalse(st.rekey_inflight)
        self.assertIsNone(st.rekey_priv)
        self.assertEqual(st.rekey_id, b"")
        self.assertEqual(st.rekey_attempts, 0)
        self.assertEqual(st.rekey_next_retry_ts, 0.0)
        self.assertEqual(st.rekey_sent_msgs, 0)

    def test_handle_rekey3_switches_responder_key(self) -> None:
        st = _PeerState()
        epoch = current_epoch_slot(now=1_700_000_602)
        st.rekey_candidate_id = b"ABCD"
        st.rekey_candidate_aes = AESGCM(b"\x33" * 32)
        st.rekey_candidate_pub = b"X" * 32
        st.rekey_candidate_ts = 10.0
        frame = parse_frame(build_rekey3_frame(rid=b"ABCD", epoch_slot=epoch))
        self.assertIsNotNone(frame)
        assert frame is not None
        out = handle_rekey3(st, frame, now=16.0, prev_key_grace_seconds=300.0, peer_norm="deadbeef")
        self.assertIn("responder", out["log"])
        self.assertIsNone(st.rekey_candidate_aes)
        self.assertEqual(st.rekey_candidate_id, b"")
        self.assertEqual(st.rekey_candidate_pub, b"")
        self.assertEqual(st.rekey_candidate_ts, 0.0)
        self.assertEqual(st.rekey_sent_msgs, 0)


if __name__ == "__main__":
    unittest.main()
