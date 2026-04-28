import os
import tempfile
import unittest


class _DummyState:
    def __init__(self) -> None:
        self.last_seen_ts = 0.0
        self.app_offline_ts = 0.0
        self.last_hello_rx_ts = 0.0
        self.last_key_ok_ts = 0.0
        self.key_confirmed_ts = 0.0
        self.await_key_confirm = False
        self.await_key_confirm_attempts = 0
        self.key_ready = True
        self.pinned_mismatch = False
        self.pinned_old_fp = ""
        self.pinned_new_fp = ""
        self.pinned_new_pub_b64 = ""
        self.force_key_req = False
        self.next_key_req_ts = 0.0
        self.aes = object()


class TestHandshake(unittest.TestCase):
    def _mk_ctx(self, *, keydir: str, packet_trace: bool = False):
        from meshtalk.handshake import HandshakeContext

        events = []
        state_by_peer = {}
        key_resp_last = {}

        def ui_emit(evt: str, payload: object) -> None:
            events.append((evt, payload))

        def get_peer_state(peer_norm):
            return state_by_peer.get(peer_norm)

        def ensure_peer_state(peer_norm: str):
            st = state_by_peer.get(peer_norm)
            if st is None:
                st = _DummyState()
                state_by_peer[peer_norm] = st
            return st

        called = {
            "store": 0,
            "force_store": 0,
            "update": 0,
            "send_kr2": 0,
            "conflict": 0,
            "confirmed": 0,
        }

        # Pluggable behavior from tests:
        store_behavior = {"mode": "ok"}  # ok | pinned_mismatch

        def store_peer_pub(peer_norm: str, pub_raw: bytes) -> None:
            called["store"] += 1
            if store_behavior["mode"] == "pinned_mismatch":
                from meshtalk.protocol import PeerKeyPinnedError

                raise PeerKeyPinnedError(peer_norm, "oldfp", "newfp")
            # normal store would persist, but handshake doesn't require it.

        def force_store_peer_pub(peer_norm: str, pub_raw: bytes) -> None:
            called["force_store"] += 1
            with open(os.path.join(keydir, f"{peer_norm}.pub"), "wb") as f:
                f.write(pub_raw)

        def update_peer_pub(peer_norm: str, pub_raw: bytes) -> None:
            called["update"] += 1
            st = ensure_peer_state(peer_norm)
            st.key_ready = True
            st.aes = object()
            st.last_key_ok_ts = 1000.0

        def should_auto_accept(peer_norm: str, st) -> tuple[bool, str]:
            return (False, "policy=strict")

        def should_auto_accept_first(peer_norm: str, st) -> tuple[bool, str]:
            return (False, "policy=strict")

        def send_kr2(peer_norm: str, payload: bytes) -> bool:
            called["send_kr2"] += 1
            return True

        def on_key_conflict(peer_norm: str, old_fp: str, new_fp: str) -> None:
            called["conflict"] += 1

        def on_key_confirmed(peer_norm: str, st, by: str) -> None:
            called["confirmed"] += 1

        def activity_record(*_a, **_kw):
            # no-op for unit tests
            return None

        ctx = HandshakeContext(
            self_id="deadbeef",
            pub_self_raw=b"\x11" * 32,
            keydir=keydir,
            key_response_min_interval_s=300.0,
            key_response_retry_interval_s=5.0,
            packet_trace=bool(packet_trace),
            peer_meta={},
            key_response_last_ts=key_resp_last,
            norm_peer_id=lambda s: (str(s or "").lstrip("!").lower() if s else None),
            wire_id_from_norm=lambda s: "!" + s,
            ts_local=lambda: "TS",
            ui_emit=ui_emit,
            activity_record=activity_record,
            get_peer_state=get_peer_state,
            ensure_peer_state=ensure_peer_state,
            update_peer_names_from_nodes=lambda _p: None,
            store_peer_pub=store_peer_pub,
            force_store_peer_pub=force_store_peer_pub,
            update_peer_pub=update_peer_pub,
            should_auto_accept_first_peer_key=should_auto_accept_first,
            should_auto_accept_peer_key_rotation=should_auto_accept,
            send_kr2=send_kr2,
            on_key_conflict=on_key_conflict,
            on_key_confirmed=on_key_confirmed,
        )
        return ctx, events, called, store_behavior, state_by_peer

    def test_broadcast_key_frame_is_ignored(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_kr1_frame

        with tempfile.TemporaryDirectory() as td:
            ctx, events, called, _store_behavior, _st = self._mk_ctx(keydir=td)
            kr1 = build_kr1_frame(b"\x22" * 32, b"abcd")
            packet = {"fromId": "!11223344", "toId": "^all"}
            handled = handle_mt2_plaintext(packet, kr1, now=1000.0, ctx=ctx)
            self.assertTrue(handled)
            self.assertEqual(called["store"], 0)
            self.assertEqual(called["send_kr2"], 0)

    def test_broadcast_key_frame_is_ignored_numeric(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_kr1_frame

        with tempfile.TemporaryDirectory() as td:
            ctx, _events, called, _store_behavior, _st = self._mk_ctx(keydir=td)
            kr1 = build_kr1_frame(b"\x22" * 32, b"abcd")
            packet = {"fromId": "!11223344", "toId": 0xFFFFFFFF}
            handled = handle_mt2_plaintext(packet, kr1, now=1000.0, ctx=ctx)
            self.assertTrue(handled)
            self.assertEqual(called["store"], 0)
            self.assertEqual(called["send_kr2"], 0)

    def test_pinned_key_mismatch_strict_calls_conflict(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_kr1_frame

        with tempfile.TemporaryDirectory() as td:
            ctx, _events, called, store_behavior, _st = self._mk_ctx(keydir=td)
            store_behavior["mode"] = "pinned_mismatch"
            with open(os.path.join(td, "11223344.pub"), "wb") as f:
                f.write(b"old")
            kr1 = build_kr1_frame(b"\x22" * 32, b"abcd")
            packet = {"fromId": "!11223344", "toId": "!deadbeef"}
            handled = handle_mt2_plaintext(packet, kr1, now=1000.0, ctx=ctx)
            self.assertTrue(handled)
            self.assertEqual(called["conflict"], 1)
            self.assertEqual(called["force_store"], 0)

    def test_first_seen_key_auto_accept_in_auto_mode(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_kr1_frame

        with tempfile.TemporaryDirectory() as td:
            ctx, events, called, _store_behavior, _st = self._mk_ctx(keydir=td)
            ctx.should_auto_accept_first_peer_key = lambda _p, _s: (True, "policy=auto")

            kr1 = build_kr1_frame(b"\x55" * 32, b"abcd")
            packet = {"fromId": "!11223344", "toId": "!deadbeef"}
            handled = handle_mt2_plaintext(packet, kr1, now=1000.0, ctx=ctx)
            self.assertTrue(handled)
            self.assertEqual(called["store"], 1)
            self.assertEqual(called["conflict"], 0)
            self.assertEqual(called["send_kr2"], 1)
            self.assertEqual(called["confirmed"], 1)
            logs = [p for (e, p) in events if e == "log" and isinstance(p, str)]
            self.assertTrue(any("trust_state peer=11223344 state=first_seen action=auto_accept" in p for p in logs))
            self.assertTrue(any("first key auto-accepted" in p for p in logs))

    def test_first_seen_key_strict_requires_manual_accept(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_kr1_frame

        with tempfile.TemporaryDirectory() as td:
            ctx, events, called, _store_behavior, _st = self._mk_ctx(keydir=td)
            ctx.should_auto_accept_first_peer_key = lambda _p, _s: (False, "policy=strict")

            kr1 = build_kr1_frame(b"\x66" * 32, b"abcd")
            packet = {"fromId": "!11223344", "toId": "!deadbeef"}
            handled = handle_mt2_plaintext(packet, kr1, now=1000.0, ctx=ctx)
            self.assertTrue(handled)
            self.assertEqual(called["send_kr2"], 0)
            self.assertEqual(called["conflict"], 1)
            logs = [p for (e, p) in events if e == "log" and isinstance(p, str)]
            self.assertTrue(any("trust_state peer=11223344 state=first_seen action=manual_accept" in p for p in logs))
            self.assertTrue(any("first key pending manual accept" in p for p in logs))

    def test_pinned_key_mismatch_auto_accept_overwrites(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_kr1_frame

        with tempfile.TemporaryDirectory() as td:
            ctx, _events, called, store_behavior, _st = self._mk_ctx(keydir=td)
            store_behavior["mode"] = "pinned_mismatch"

            # override policy to auto-accept
            ctx.should_auto_accept_peer_key_rotation = lambda _p, _s: (True, "policy=auto")

            # create pinned file so auto-accept branch attempts removal
            pinned_path = os.path.join(td, "11223344.pub")
            with open(pinned_path, "wb") as f:
                f.write(b"old")

            kr1 = build_kr1_frame(b"\x33" * 32, b"abcd")
            packet = {"fromId": "!11223344", "toId": "!deadbeef"}
            handled = handle_mt2_plaintext(packet, kr1, now=1000.0, ctx=ctx)
            self.assertTrue(handled)
            self.assertEqual(called["conflict"], 0)
            self.assertEqual(called["force_store"], 1)
            logs = [p for (e, p) in _events if e == "log" and isinstance(p, str)]
            self.assertTrue(any("trust_state peer=11223344 state=pinned_rotation action=auto_accept" in p for p in logs))

    def test_pinned_key_mismatch_auto_accept_failure_keeps_old_pinned_file(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_kr1_frame

        with tempfile.TemporaryDirectory() as td:
            ctx, _events, called, store_behavior, _st = self._mk_ctx(keydir=td)
            store_behavior["mode"] = "pinned_mismatch"
            ctx.should_auto_accept_peer_key_rotation = lambda _p, _s: (True, "policy=auto")
            ctx.force_store_peer_pub = lambda _peer_norm, _pub_raw: (_ for _ in ()).throw(RuntimeError("disk full"))

            pinned_path = os.path.join(td, "11223344.pub")
            with open(pinned_path, "wb") as f:
                f.write(b"old")

            kr1 = build_kr1_frame(b"\x44" * 32, b"abcd")
            packet = {"fromId": "!11223344", "toId": "!deadbeef"}
            handled = handle_mt2_plaintext(packet, kr1, now=1000.0, ctx=ctx)
            self.assertTrue(handled)
            self.assertEqual(called["conflict"], 1)
            with open(pinned_path, "rb") as f:
                self.assertEqual(f.read(), b"old")

    def test_resp_confirmation_resets_await_confirm_attempts(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_kr2_frame

        with tempfile.TemporaryDirectory() as td:
            ctx, events, _called, _store_behavior, state_by_peer = self._mk_ctx(keydir=td)
            ctx.should_auto_accept_first_peer_key = lambda _p, _s: (True, "policy=auto")
            st = _DummyState()
            st.await_key_confirm = True
            st.await_key_confirm_attempts = 4
            state_by_peer["11223344"] = st

            kr2 = build_kr2_frame(b"\x77" * 32, b"abcd")
            packet = {"fromId": "!11223344", "toId": "!deadbeef"}
            handled = handle_mt2_plaintext(packet, kr2, now=1000.0, ctx=ctx)
            self.assertTrue(handled)
            self.assertFalse(st.await_key_confirm)
            self.assertEqual(st.await_key_confirm_attempts, 0)
            logs = [p for (e, p) in events if e == "log" and isinstance(p, str)]
            self.assertTrue(any("KEYOK: confirmed_by=resp" in p for p in logs))

    def test_hello_throttle_without_packet_trace(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_hello_frame

        with tempfile.TemporaryDirectory() as td:
            ctx, events, _called, _store_behavior, _st = self._mk_ctx(keydir=td, packet_trace=False)
            hello = build_hello_frame(b"abcd")
            packet = {"fromId": "!11223344", "toId": "^all", "rxRssi": -10, "rxSnr": 5.0, "hopStart": 2, "hopLimit": 2}
            self.assertTrue(handle_mt2_plaintext(packet, hello, now=100.0, ctx=ctx))
            self.assertTrue(handle_mt2_plaintext(packet, hello, now=120.0, ctx=ctx))  # within 60s
            logs = [p for (e, p) in events if e == "log" and isinstance(p, str) and "DISCOVERY: hello rx" in p]
            self.assertEqual(len(logs), 1)

    def test_hello_no_throttle_with_packet_trace(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_hello_frame

        with tempfile.TemporaryDirectory() as td:
            ctx, events, _called, _store_behavior, _st = self._mk_ctx(keydir=td, packet_trace=True)
            hello = build_hello_frame(b"abcd")
            packet = {"fromId": "!11223344", "toId": "^all"}
            self.assertTrue(handle_mt2_plaintext(packet, hello, now=100.0, ctx=ctx))
            self.assertTrue(handle_mt2_plaintext(packet, hello, now=120.0, ctx=ctx))
            logs = [p for (e, p) in events if e == "log" and isinstance(p, str) and "DISCOVERY: hello rx" in p]
            self.assertEqual(len(logs), 2)

    def test_self_id_key_frame_is_ignored(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_kr1_frame

        with tempfile.TemporaryDirectory() as td:
            ctx, _events, called, _store_behavior, _st = self._mk_ctx(keydir=td)
            kr1 = build_kr1_frame(b"\x22" * 32, b"abcd")
            packet = {"fromId": "!deadbeef", "toId": "!deadbeef"}
            handled = handle_mt2_plaintext(packet, kr1, now=1000.0, ctx=ctx)
            self.assertTrue(handled)
            self.assertEqual(called["store"], 0)
            self.assertEqual(called["update"], 0)
            self.assertEqual(called["send_kr2"], 0)

    def test_invalid_from_id_key_frame_is_rejected(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_kr1_frame

        with tempfile.TemporaryDirectory() as td:
            ctx, _events, called, _store_behavior, _st = self._mk_ctx(keydir=td)
            kr1 = build_kr1_frame(b"\x22" * 32, b"abcd")
            packet = {"fromId": "!../../bad", "toId": "!deadbeef"}
            handled = handle_mt2_plaintext(packet, kr1, now=1000.0, ctx=ctx)
            self.assertTrue(handled)
            self.assertEqual(called["store"], 0)
            self.assertEqual(called["update"], 0)
            self.assertEqual(called["send_kr2"], 0)

    def test_remote_initiated_key_exchange_sets_confirmed_timestamp(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_kr1_frame

        with tempfile.TemporaryDirectory() as td:
            ctx, _events, called, _store_behavior, state_by_peer = self._mk_ctx(keydir=td)
            peer = "11223344"
            with open(os.path.join(td, f"{peer}.pub"), "wb") as f:
                f.write(b"old")
            state_by_peer[peer] = _DummyState()
            state_by_peer[peer].key_ready = True
            state_by_peer[peer].await_key_confirm = False

            kr1 = build_kr1_frame(b"\x22" * 32, b"abcd")
            packet = {"fromId": f"!{peer}", "toId": "!deadbeef"}
            handled = handle_mt2_plaintext(packet, kr1, now=1000.0, ctx=ctx)
            self.assertTrue(handled)
            self.assertEqual(called["send_kr2"], 1)
            self.assertGreater(state_by_peer[peer].key_confirmed_ts, 0.0)
            self.assertGreater(state_by_peer[peer].last_key_ok_ts, 0.0)

    def test_first_key_requires_manual_accept(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_kr1_frame

        with tempfile.TemporaryDirectory() as td:
            ctx, _events, called, _store_behavior, state_by_peer = self._mk_ctx(keydir=td)
            peer = "11223344"
            state_by_peer[peer] = _DummyState()
            state_by_peer[peer].key_ready = False
            kr1 = build_kr1_frame(b"\x22" * 32, b"abcd")
            packet = {"fromId": f"!{peer}", "toId": "!deadbeef"}
            handled = handle_mt2_plaintext(packet, kr1, now=1000.0, ctx=ctx)
            self.assertTrue(handled)
            self.assertEqual(called["store"], 0)
            self.assertEqual(called["send_kr2"], 0)
            self.assertEqual(called["conflict"], 1)
            self.assertTrue(state_by_peer[peer].pinned_mismatch)
            self.assertTrue(state_by_peer[peer].pinned_new_pub_b64)

    def test_duplicate_key_frame_nonce_is_suppressed(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_kr1_frame

        with tempfile.TemporaryDirectory() as td:
            peer = "11223344"
            with open(os.path.join(td, f"{peer}.pub"), "wb") as f:
                f.write(b"old")
            ctx, _events, called, _store_behavior, _st = self._mk_ctx(keydir=td)
            kr1 = build_kr1_frame(b"\x22" * 32, b"abcd")
            packet = {"fromId": f"!{peer}", "toId": "!deadbeef"}
            self.assertTrue(handle_mt2_plaintext(packet, kr1, now=1000.0, ctx=ctx))
            self.assertTrue(handle_mt2_plaintext(packet, kr1, now=1001.0, ctx=ctx))
            self.assertEqual(called["store"], 1)

    def test_duplicate_key_frame_is_suppressed_after_interleaved_other_nonce(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_kr1_frame

        with tempfile.TemporaryDirectory() as td:
            peer = "11223344"
            with open(os.path.join(td, f"{peer}.pub"), "wb") as f:
                f.write(b"old")
            ctx, events, called, _store_behavior, _st = self._mk_ctx(keydir=td)
            ctx.key_response_min_interval_s = 0.0
            packet = {"fromId": f"!{peer}", "toId": "!deadbeef"}
            kr1_a = build_kr1_frame(b"\x22" * 32, b"abcd")
            kr1_b = build_kr1_frame(b"\x22" * 32, b"abce")

            self.assertTrue(handle_mt2_plaintext(packet, kr1_a, now=1000.0, ctx=ctx))
            self.assertTrue(handle_mt2_plaintext(packet, kr1_b, now=1001.0, ctx=ctx))
            self.assertTrue(handle_mt2_plaintext(packet, kr1_a, now=1002.0, ctx=ctx))

            self.assertEqual(called["store"], 2)
            logs = [p for (e, p) in events if e == "log" and isinstance(p, str)]
            self.assertTrue(any("duplicate key frame suppressed peer=11223344 kind=req" in p for p in logs))

    def test_rotation_oscillation_requires_manual_accept(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_kr1_frame

        with tempfile.TemporaryDirectory() as td:
            peer = "11223344"
            pinned_path = os.path.join(td, f"{peer}.pub")
            with open(pinned_path, "wb") as f:
                f.write(b"old")

            ctx, events, called, store_behavior, _st = self._mk_ctx(keydir=td)
            store_behavior["mode"] = "pinned_mismatch"
            ctx.should_auto_accept_peer_key_rotation = lambda _p, _s: (True, "policy=auto")
            ctx.peer_meta[peer] = {
                "last_auto_rotation_old_fp": "newfp",
                "last_auto_rotation_new_fp": "oldfp",
                "last_auto_rotation_ts": 995.0,
            }

            kr1 = build_kr1_frame(b"\x33" * 32, b"abcd")
            packet = {"fromId": f"!{peer}", "toId": "!deadbeef"}
            handled = handle_mt2_plaintext(packet, kr1, now=1000.0, ctx=ctx)

            self.assertTrue(handled)
            self.assertEqual(called["force_store"], 0)
            self.assertEqual(called["conflict"], 1)
            logs = [p for (e, p) in events if e == "log" and isinstance(p, str)]
            self.assertTrue(any("state=pinned_rotation action=manual_accept" in p and "rotation_oscillation" in p for p in logs))

    def test_same_key_repeated_req_skips_runtime_refresh(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_kr1_frame

        with tempfile.TemporaryDirectory() as td:
            peer = "11223344"
            with open(os.path.join(td, f"{peer}.pub"), "wb") as f:
                f.write(b"\x22" * 32)
            ctx, events, called, _store_behavior, state_by_peer = self._mk_ctx(keydir=td)
            state_by_peer[peer] = _DummyState()
            state_by_peer[peer].key_ready = True
            packet = {"fromId": f"!{peer}", "toId": "!deadbeef"}
            kr1_a = build_kr1_frame(b"\x22" * 32, b"abcd")
            kr1_b = build_kr1_frame(b"\x22" * 32, b"abce")

            self.assertTrue(handle_mt2_plaintext(packet, kr1_a, now=1000.0, ctx=ctx))
            self.assertTrue(handle_mt2_plaintext(packet, kr1_b, now=1001.0, ctx=ctx))

            self.assertEqual(called["store"], 1)
            self.assertEqual(called["update"], 1)
            logs = [p for (e, p) in events if e == "log" and isinstance(p, str)]
            self.assertTrue(any("request refresh skipped peer=11223344 reason=recent_same_key" in p for p in logs))

    def test_key_request_log_is_debounced_for_burst(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_kr1_frame

        with tempfile.TemporaryDirectory() as td:
            peer = "11223344"
            with open(os.path.join(td, f"{peer}.pub"), "wb") as f:
                f.write(b"\x22" * 32)
            ctx, events, _called, _store_behavior, state_by_peer = self._mk_ctx(keydir=td)
            state_by_peer[peer] = _DummyState()
            state_by_peer[peer].key_ready = True
            packet = {"fromId": f"!{peer}", "toId": "!deadbeef"}
            kr1_a = build_kr1_frame(b"\x22" * 32, b"abcd")
            kr1_b = build_kr1_frame(b"\x22" * 32, b"abce")

            self.assertTrue(handle_mt2_plaintext(packet, kr1_a, now=1000.0, ctx=ctx))
            self.assertTrue(handle_mt2_plaintext(packet, kr1_b, now=1001.0, ctx=ctx))

            logs = [p for (e, p) in events if e == "log" and isinstance(p, str) and "KEY: request from 11223344 initiator=remote event=req frame=KR1" in p]
            self.assertEqual(len(logs), 1)

    def test_global_key_response_throttle(self):
        from meshtalk.handshake import handle_mt2_plaintext
        from meshtalk.mt2_frames import build_kr1_frame

        with tempfile.TemporaryDirectory() as td:
            peer1 = "11223344"
            peer2 = "11223345"
            with open(os.path.join(td, f"{peer1}.pub"), "wb") as f:
                f.write(b"old")
            with open(os.path.join(td, f"{peer2}.pub"), "wb") as f:
                f.write(b"old")
            ctx, _events, called, _store_behavior, _st = self._mk_ctx(keydir=td)
            kr1_a = build_kr1_frame(b"\x22" * 32, b"abcd")
            kr1_b = build_kr1_frame(b"\x33" * 32, b"abce")
            self.assertTrue(handle_mt2_plaintext({"fromId": f"!{peer1}", "toId": "!deadbeef"}, kr1_a, now=1000.0, ctx=ctx))
            self.assertTrue(handle_mt2_plaintext({"fromId": f"!{peer2}", "toId": "!deadbeef"}, kr1_b, now=1000.2, ctx=ctx))
            self.assertEqual(called["send_kr2"], 1)


if __name__ == "__main__":
    unittest.main()
