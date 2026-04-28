import unittest

from meshtalk.v3_radio import send_packet, send_traceroute_request, send_wire_payload, try_send_packet_nowait


class _Iface:
    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []

    def sendData(self, payload, **kwargs):
        if self.fail:
            raise RuntimeError("boom")
        self.calls.append((payload, kwargs))


class _TraceIface:
    def __init__(self, mode):
        self.mode = mode
        self.calls = []

    def sendData(self, payload, **kwargs):
        self.calls.append((payload, kwargs))
        idx = len(self.calls)
        if self.mode == "full":
            return
        if self.mode == "drop_hop" and idx == 1 and "hopLimit" in kwargs:
            raise TypeError("no hopLimit")
        if self.mode == "drop_channel" and (
            (idx == 1 and "hopLimit" in kwargs) or (idx == 2 and "channelIndex" in kwargs)
        ):
            raise TypeError("older signature")


class V3RadioTests(unittest.TestCase):
    def test_send_packet_success(self) -> None:
        iface = _Iface()
        emits = []
        traces = []
        ok = send_packet(
            interface=iface,
            payload=b"abc",
            destination_id="!peer",
            port_num=1,
            channel_index=0,
            trace_context="ctx",
            trace_suppressed_fn=lambda ctx, ex: traces.append((ctx, str(ex))),
            ui_emit_fn=lambda name, payload: emits.append((name, payload)),
            log_packet_trace=False,
            log_line="",
        )
        self.assertTrue(ok)
        self.assertEqual(len(iface.calls), 1)
        self.assertEqual(emits, [])
        self.assertEqual(traces, [])

    def test_send_wire_payload_success(self) -> None:
        iface = _Iface()
        emits = []
        traces = []
        ok = send_wire_payload(
            interface=iface,
            payload=b"abc",
            destination_id="!peer",
            port_num=1,
            channel_index=0,
            trace_context="ctx",
            trace_suppressed_fn=lambda ctx, ex: traces.append((ctx, str(ex))),
            ui_emit_fn=lambda name, payload: emits.append((name, payload)),
            log_packet_trace=True,
            log_line="LOG",
        )
        self.assertTrue(ok)
        self.assertEqual(len(iface.calls), 1)
        self.assertEqual(emits, [("log", "LOG")])
        self.assertEqual(traces, [])

    def test_send_wire_payload_failure(self) -> None:
        iface = _Iface(fail=True)
        emits = []
        traces = []
        ok = send_wire_payload(
            interface=iface,
            payload=b"abc",
            destination_id="!peer",
            port_num=1,
            channel_index=0,
            trace_context="ctx",
            trace_suppressed_fn=lambda ctx, ex: traces.append((ctx, str(ex))),
            ui_emit_fn=lambda name, payload: emits.append((name, payload)),
            log_packet_trace=True,
            log_line="LOG",
        )
        self.assertFalse(ok)
        self.assertEqual(traces[0][0], "ctx")
        self.assertEqual(emits, [("radio_lost", None)])

    def test_send_traceroute_request_fallbacks(self) -> None:
        for mode, expected_calls in (("full", 1), ("drop_hop", 2), ("drop_channel", 3)):
            iface = _TraceIface(mode)
            send_traceroute_request(
                interface=iface,
                req=b"x",
                destination_id="!peer",
                traceroute_port_num=99,
                on_response=lambda *args, **kwargs: None,
                channel_index=2,
                hop_limit=7,
            )
            self.assertEqual(len(iface.calls), expected_calls)

    def test_try_send_packet_nowait_success(self) -> None:
        iface = _Iface()
        ok = try_send_packet_nowait(
            interface=iface,
            payload=b"abc",
            destination_id="!peer",
            port_num=1,
            channel_index=0,
            trace_context="ctx",
            trace_suppressed_fn=lambda *_args: None,
            ui_emit_fn=lambda *_args: None,
            log_packet_trace=False,
            log_line="",
        )
        self.assertTrue(ok)
        self.assertEqual(len(iface.calls), 1)


if __name__ == "__main__":
    unittest.main()
