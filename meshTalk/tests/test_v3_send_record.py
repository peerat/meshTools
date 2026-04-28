import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from meshtalk.v3_send_record import apply_post_send_state, prepare_record_send, record_is_expired, record_retry_due


class _PeerState:
    pass


class V3SendRecordTests(unittest.TestCase):
    def test_record_expiry_and_retry_due(self) -> None:
        rec = {"created": 10.0, "next_retry_at": 30.0}
        self.assertFalse(record_is_expired(rec, now=15.0, max_seconds=10.0))
        self.assertTrue(record_is_expired(rec, now=25.1, max_seconds=10.0))
        self.assertFalse(record_retry_due(rec, now=29.9))
        self.assertTrue(record_retry_due(rec, now=30.0))

    def test_prepare_record_send(self) -> None:
        rec = {"attempts": 1, "text": "hello", "cmp": "bz2"}
        plan = prepare_record_send(
            rec,
            now=10.0,
            max_plain=10,
            max_bytes=20,
            build_wire_pt_fn=lambda _rec, _attempt: b"abc",
            pack_payload_fn=lambda _rec, _ts: b"12345",
        )
        self.assertEqual(plan["status"], "ready")
        self.assertEqual(plan["attempts_next"], 2)
        self.assertEqual(plan["cmp_name"], "bz2")
        self.assertEqual(plan["payload"], b"12345")
        drop = prepare_record_send(
            rec,
            now=10.0,
            max_plain=2,
            max_bytes=20,
            build_wire_pt_fn=lambda _rec, _attempt: b"abc",
            pack_payload_fn=lambda _rec, _ts: b"12345",
        )
        self.assertEqual(drop["status"], "drop")
        self.assertEqual(drop["reason"], "too_long")

    def test_apply_post_send_state(self) -> None:
        rec = {"attempts": 0}
        st = _PeerState()
        out = apply_post_send_state(
            rec,
            now=10.0,
            attempts_next=1,
            fast_profile=(1, 100, 100),
            schedule_next_retry_fn=lambda _rec, _st, _now, _retry_s, _attempts: 7.0,
            peer_state=st,
            retry_seconds=15.0,
        )
        self.assertEqual(out["attempts"], 1)
        self.assertEqual(rec["attempts"], 1)
        self.assertEqual(rec["last_send"], 10.0)
        self.assertEqual(rec["next_retry_at"], 17.0)
        self.assertEqual(rec["fast_left"], 1)
        self.assertEqual(rec["fast_min_ms"], 100)
        self.assertEqual(rec["fast_max_ms"], 100)
        self.assertEqual(rec["micro_retries_sent"], 0)


if __name__ == "__main__":
    unittest.main()
